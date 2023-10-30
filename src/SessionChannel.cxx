// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SessionChannel.hxx"
#include "Connection.hxx"
#include "DebugMode.hxx"
#include "spawn/Interface.hxx"
#include "spawn/Prepared.hxx"
#include "spawn/ProcessHandle.hxx"
#include "ssh/Deserializer.hxx"
#include "ssh/CConnection.hxx"
#include "ssh/TerminalMode.hxx"
#include "system/Error.hxx"
#include "util/StringAPI.hxx"
#include "AllocatorPtr.hxx"

#ifdef ENABLE_TRANSLATION
#include "translation/Response.hxx"
#endif // ENABLE_TRANSLATION

#include <fmt/core.h>

#include <pty.h> // for openpty()
#include <signal.h>
#include <sys/wait.h> // for WCOREDUMP()
#include <unistd.h>
#include <utmp.h> // for login_tty()

using std::string_view_literals::operator""sv;

SessionChannel::SessionChannel(SpawnService &_spawn_service,
			       SSH::CConnection &_connection,
			       SSH::ChannelInit init) noexcept
	:SSH::Channel(_connection, init, RECEIVE_WINDOW),
	 spawn_service(_spawn_service),
	 stdout_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStdoutReady)),
	 stderr_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStderrReady)),
	 tty(_connection.GetEventLoop(), BIND_THIS_METHOD(OnTtyReady))
{
}

SessionChannel::~SessionChannel() noexcept
{
	stdout_pipe.Close();
	stderr_pipe.Close();

	if (child)
		child->Kill(SIGTERM);
}

void
SessionChannel::CloseIfInactive() noexcept
{
	if (!IsActive())
		Close();
}

void
SessionChannel::SetEnv(std::string_view name, std::string_view value) noexcept
{
	// TODO check if already exists?

	env.emplace_front(fmt::format("{}={}", name, value));
}

void
SessionChannel::OnWindowAdjust(std::size_t nbytes)
{
	if (GetSendWindow() == 0)
		/* re-schedule all read events, because we are now
		   allowed to send data again */
		ScheduleRead();

	Channel::OnWindowAdjust(nbytes);
}

void
SessionChannel::OnData(std::span<const std::byte> payload)
{
	if (stdin_pipe.IsDefined())
		stdin_pipe.Write(payload);
	else if (tty.IsDefined())
		tty.GetFileDescriptor().Write(payload);

	if (ConsumeReceiveWindow(payload.size()) < RECEIVE_WINDOW/ 2)
		SendWindowAdjust(RECEIVE_WINDOW - GetReceiveWindow());
}

void
SessionChannel::OnEof()
{
	stdin_pipe.Close();
	CloseIfInactive();
}

static const char *
LoginShellName(AllocatorPtr alloc, const char *shell) noexcept
{
	const char *slash = strrchr(shell, '/');
	if (slash != nullptr && slash[1] != 0)
		shell = slash + 1;

	return alloc.Concat('-', shell);
}

void
SessionChannel::PrepareChildProcess(PreparedChildProcess &p)
{
	const auto &c = static_cast<Connection &>(GetConnection());

	const std::string_view username = c.GetUsername();
	p.SetEnv("USER", username);
	p.SetEnv("LOGNAME", username);

#ifdef ENABLE_TRANSLATION
	if (const auto *tr = c.GetTranslationResponse()) {
		tr->child_options.CopyTo(p);
	} else {
#endif // ENABLE_TRANSLATION
		// TODO
		if (!debug_mode) {
			p.uid_gid.uid = 65535;
			p.uid_gid.gid = 65535;
		}

		p.ns.mount.home = getenv("HOME");
#ifdef ENABLE_TRANSLATION
	}
#endif // ENABLE_TRANSLATION

	if (tty.IsDefined()) {
		p.stdin_fd = p.stdout_fd = p.stderr_fd = slave_tty.Release();
		p.tty = true;
		p.ns.mount.mount_pts = true;
	} else {
		UniqueFileDescriptor stdin_r, stdout_r, stdout_w, stderr_r, stderr_w;
		if (!UniqueFileDescriptor::CreatePipe(stdin_r, stdin_pipe) ||
		    !UniqueFileDescriptor::CreatePipe(stdout_r, stdout_w) ||
		    !UniqueFileDescriptor::CreatePipe(stderr_r, stderr_w))
			throw MakeErrno("Failed to create pipe");

		p.SetStdin(std::move(stdin_r));
		p.SetStdout(std::move(stdout_w));
		p.SetStderr(std::move(stderr_w));

		stdout_pipe.Open(stdout_r.Release());
		stderr_pipe.Open(stderr_r.Release());
	}

	if (const char *home = p.ns.mount.GetJailedHome()) {
		p.SetEnv("HOME", home);
		p.chdir = home;
	}
}

void
SessionChannel::SpawnChildProcess(PreparedChildProcess &&p)
{
	if (GetSendWindow() > 0)
		ScheduleRead();

	for (const auto &i : env)
		p.PutEnv(i.c_str());

	// TODO use a proper process name
	child = spawn_service.SpawnChildProcess("foo", std::move(p));
	child->SetExitListener(*this);
}

bool
SessionChannel::Exec(const char *cmd)
{
	const auto &c = static_cast<Connection &>(GetConnection());

	Allocator alloc;
	PreparedChildProcess p;

	PrepareChildProcess(p);

	const char *shell = cmd != nullptr ? "/bin/sh" : "/bin/bash";

#ifdef ENABLE_TRANSLATION
	if (const auto *tr = c.GetTranslationResponse()) {
		if (tr->shell != nullptr)
			shell = tr->shell;

		if (tr->token != nullptr &&
		    StringIsEqual(tr->token, "sftp-only"))
			/* the translation server asks us not to
			   provide this user with a shell */
			return false;
	}
#endif // ENABLE_TRANSLATION

	if (cmd != nullptr) {
		p.args.push_back(shell);
		p.args.push_back("-c");
		p.args.push_back(cmd);
	} else {
		p.exec_path = shell;
		p.args.push_back(LoginShellName(alloc, shell));
	}

	SpawnChildProcess(std::move(p));

	return true;
}

static void
ApplyTerminalModes(FileDescriptor fd, std::span<const std::byte> src) noexcept
{
	struct termios tio;

	if (tcgetattr(fd.Get(), &tio) < 0)
		return;

	SSH::ParseTerminalModes(tio, src);
	tcsetattr(fd.Get(), TCSANOW, &tio);
}

bool
SessionChannel::OnRequest(std::string_view request_type,
			  std::span<const std::byte> type_specific)
{
	fmt::print(stderr, "ChannelRequest '{}'\n", request_type);

	if (WasStarted())
		/* the program was already started, and there's no
		   point in handling further requests */
		return false;

	if (request_type == "exec"sv) {
		SSH::Deserializer d{type_specific};
		const std::string command{d.ReadString()};
		fmt::print(stderr, "  exec '{}'\n", command);

		return Exec(command.c_str());
	} else if (request_type == "shell"sv) {
		return Exec(nullptr);
	} else if (request_type == "subsystem"sv) {
		SSH::Deserializer d{type_specific};
		const std::string_view subsystem_name{d.ReadString()};

		fmt::print(stderr, "  subsystem '{}'\n", subsystem_name);

		if (subsystem_name == "sftp"sv) {
			// TODO repeat translation request with service="sftp"

			if (tty.IsDefined())
				/* refuse to run sftp with a pty */
				return false;

			Allocator alloc;
			PreparedChildProcess p;

			PrepareChildProcess(p);

			p.Append("/usr/lib/openssh/sftp-server");

			SpawnChildProcess(std::move(p));
			return true;
		} else
			return false;
	} else if (request_type == "pty-req"sv) {
		struct winsize ws{};

		SSH::Deserializer d{type_specific};
		const auto term = d.ReadString();
		ws.ws_col = d.ReadU32();
		ws.ws_row = d.ReadU32();
		ws.ws_xpixel = d.ReadU32();
		ws.ws_ypixel = d.ReadU32();
		const auto encoded_terminal_modes = d.ReadLengthEncoded();

		int master, slave;

		if (openpty(&master, &slave, nullptr, nullptr, &ws) < 0)
			throw MakeErrno("openpty() failed");

		slave_tty = UniqueFileDescriptor{slave};
		slave_tty.EnableCloseOnExec();

		tty.Close();
		tty.Open(FileDescriptor{master});
		tty.GetFileDescriptor().EnableCloseOnExec();

		if (!encoded_terminal_modes.empty())
			ApplyTerminalModes(slave_tty, encoded_terminal_modes);

		SetEnv("TERM"sv, term);

		return true;
	} else if (request_type == "env"sv) {
		SSH::Deserializer d{type_specific};
		const auto name = d.ReadString();
		const auto value = d.ReadString();

		SetEnv(name, value);
		return true;
	} else
		return false;

	// TOOD "signal"
}

void
SessionChannel::OnTtyReady([[maybe_unused]] unsigned events) noexcept
{
	if (events == PipeEvent::HANGUP) {
		tty.Close();
		SendEof();
		CloseIfInactive();
		return;
	}

	std::byte buffer[4096];
	std::span<std::byte> dest{buffer};

	if (GetSendWindow() < dest.size()) {
		dest = dest.first(GetSendWindow());
		assert(!dest.empty());
	}

	auto nbytes = tty.GetFileDescriptor().Read(dest);
	if (nbytes > 0) {
		SendData(dest.first(nbytes));

		if (GetSendWindow() == 0)
			CancelRead();
	} else {
		tty.Close();
		SendEof();
		CloseIfInactive();
	}
}

void
SessionChannel::OnStdoutReady([[maybe_unused]] unsigned events) noexcept
{
	std::byte buffer[4096];
	std::span<std::byte> dest{buffer};
	if (GetSendWindow() < dest.size()) {
		dest = dest.first(GetSendWindow());
		assert(!dest.empty());
	}

	auto nbytes = stdout_pipe.GetFileDescriptor().Read(dest);
	if (nbytes > 0) {
		SendData(dest.first(nbytes));

		if (GetSendWindow() == 0)
			CancelRead();
	} else {
		stdout_pipe.Close();
		SendEof();
		CloseIfInactive();
	}
}

void
SessionChannel::OnStderrReady([[maybe_unused]] unsigned events) noexcept
{
	std::byte buffer[4096];
	std::span<std::byte> dest{buffer};
	if (GetSendWindow() < dest.size()) {
		dest = dest.first(GetSendWindow());
		assert(!dest.empty());
	}

	auto nbytes = stderr_pipe.GetFileDescriptor().Read(dest);
	if (nbytes > 0) {
		SendStderr(dest.first(nbytes));

		if (GetSendWindow() == 0)
			CancelRead();
	} else {
		stderr_pipe.Close();
		CloseIfInactive();
	}
}

void
SessionChannel::OnChildProcessExit(int status) noexcept
{
	if (WIFSIGNALED(status)) {
		const char *signal_name = sigdescr_np(WTERMSIG(status));

		SendExitSignal(signal_name != nullptr ? signal_name : "UNKNOWN",
			       WCOREDUMP(status),
			       {});
	} else {
		SendExitStatus(WEXITSTATUS(status));
	}

	// TODO submit status via "exit-status" or "exit-signal"
	(void)status;

	child = {};

	CloseIfInactive();
}
