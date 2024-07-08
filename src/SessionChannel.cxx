// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SessionChannel.hxx"
#include "Connection.hxx"
#include "DebugMode.hxx"
#include "spawn/Interface.hxx"
#include "spawn/Mount.hxx"
#include "spawn/Prepared.hxx"
#include "spawn/ProcessHandle.hxx"
#include "spawn/CoEnqueue.hxx"
#include "spawn/CoWaitSpawnCompletion.hxx"
#include "ssh/Deserializer.hxx"
#include "ssh/CConnection.hxx"
#include "ssh/TerminalMode.hxx"
#include "lib/fmt/ExceptionFormatter.hxx"
#include "co/Task.hxx"
#include "system/Error.hxx"
#include "net/ToString.hxx"
#include "io/FdHolder.hxx"
#include "io/Pipe.hxx"
#include "util/StringAPI.hxx"
#include "AllocatorPtr.hxx"

#ifdef ENABLE_TRANSLATION
#include "translation/Response.hxx"
#endif // ENABLE_TRANSLATION

#include <fmt/core.h>

#include <tuple> // for std::tie()

#include <fcntl.h>
#include <pty.h> // for openpty()
#include <signal.h>
#include <sys/wait.h> // for WCOREDUMP()
#include <unistd.h>
#include <utmp.h> // for login_tty()

using std::string_view_literals::operator""sv;

SessionChannel::SessionChannel(SSH::CConnection &_connection,
			       SSH::ChannelInit init) noexcept
	:SSH::BufferedChannel(_connection, init, RECEIVE_WINDOW),
	 logger(static_cast<Connection &>(GetConnection()).GetLogger()),
	 stdin_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStdinReady)),
	 stdout_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStdoutReady)),
	 stderr_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStderrReady)),
	 tty(_connection.GetEventLoop(), BIND_THIS_METHOD(OnTtyReady))
{
}

SessionChannel::~SessionChannel() noexcept
{
	stdin_pipe.Close();
	stdout_pipe.Close();
	stderr_pipe.Close();
	tty.Close();
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

std::size_t
SessionChannel::OnBufferedData(std::span<const std::byte> payload)
{
	ssize_t nbytes;

	if (stdin_pipe.IsDefined())
		nbytes = stdin_pipe.GetFileDescriptor().Write(payload);
	else if (tty.IsDefined())
		nbytes = tty.GetFileDescriptor().Write(payload);
	else
		/* do not update receive window if there's no
		   destination */
		return payload.size();

	if (nbytes < 0) {
		const int e = errno;
		if (e == EAGAIN) {
			if (stdin_pipe.IsDefined())
				stdin_pipe.ScheduleWrite();
			else
				tty.ScheduleWrite();

			return 0;
		} else {
			// TODO log error?
			stdin_pipe.Close();
			return payload.size();
		}
	}

	const std::size_t consumed = static_cast<std::size_t>(nbytes);
	if (consumed < payload.size()) {
		if (stdin_pipe.IsDefined())
			stdin_pipe.ScheduleWrite();
		else
			tty.ScheduleWrite();
	}

	if (ConsumeReceiveWindow(consumed) < RECEIVE_WINDOW/ 2)
		SendWindowAdjust(RECEIVE_WINDOW - GetReceiveWindow());

	return consumed;
}

void
SessionChannel::OnBufferedEof()
{
	stdin_pipe.Close();
}

static std::string
LoginShellName(const char *shell) noexcept
{
	const char *slash = strrchr(shell, '/');
	if (slash != nullptr && slash[1] != 0)
		shell = slash + 1;

	return fmt::format("-{}"sv, shell);
}

void
SessionChannel::PrepareChildProcess(PreparedChildProcess &p,
				    FdHolder &close_fds,
				    bool sftp)
{
	const auto &c = static_cast<Connection &>(GetConnection());

	const std::string_view username = c.GetUsername();
	p.SetEnv("USER", username);
	p.SetEnv("LOGNAME", username);

	if (!sftp) {
		const auto peer_address = c.GetPeerAddress();
		const auto local_address = c.GetLocalAddress();
		const auto peer_host = HostToString(peer_address);
		const auto local_host = HostToString(c.GetLocalAddress());

		p.SetEnv("SSH_CLIENT",
			 fmt::format("{} {} {}",
				     peer_host, peer_address.GetPort(),
				     local_address.GetPort()));

		p.SetEnv("SSH_CONNECTION",
			 fmt::format("{} {} {} {}",
				     peer_host, peer_address.GetPort(),
				     local_host, local_address.GetPort()));
	}

	c.PrepareChildProcess(p, close_fds, sftp);

	if (tty.IsDefined()) {
		assert(!sftp);

		p.stdin_fd = p.stdout_fd = p.stderr_fd = close_fds.Insert(std::move(slave_tty));
		p.tty = true;
		p.ns.mount.mount_pts = !debug_mode;
	} else {
		auto [stdin_r, stdin_w] = CreatePipe();
		auto [stdout_r, stdout_w] = CreatePipe();
		auto [stderr_r, stderr_w] = CreatePipe();

		/* allocate 256 kB for each pipe to maximize
		   throughput */
		constexpr int PIPE_BUFFER_SIZE = 256 * 1024;
		fcntl(stdout_w.Get(), F_SETPIPE_SZ, PIPE_BUFFER_SIZE);
		fcntl(stdin_w.Get(), F_SETPIPE_SZ, PIPE_BUFFER_SIZE);

		p.stdin_fd = close_fds.Insert(std::move(stdin_r));
		p.stdout_fd = close_fds.Insert(std::move(stdout_w));
		p.stderr_fd = close_fds.Insert(std::move(stderr_w));

		stdin_w.SetNonBlocking();
		stdin_pipe.Open(stdin_w.Release());
		stdout_pipe.Open(stdout_r.Release());
		stderr_pipe.Open(stderr_r.Release());
	}

	if (const char *home = p.ns.mount.GetJailedHome()) {
		p.SetEnv("HOME", home);
		p.chdir = home;
	}

	p.SetEnv("SHELL", c.GetShell());
}

void
SessionChannel::SpawnChildProcess(PreparedChildProcess &&p)
{
	auto &c = static_cast<Connection &>(GetConnection());
	auto &spawn_service = c.GetSpawnService();

	if (GetSendWindow() > 0)
		ScheduleRead();

	for (const auto &i : env)
		p.PutEnv(i.c_str());

	Allocator alloc;
	if (c.GetAuthorizedKeyOptions().home_read_only &&
	    p.ns.mount.HasMountHome()) {
		p.ns.mount.mounts = Mount::CloneAll(alloc, p.ns.mount.mounts);

		const char *const home = p.ns.mount.home;

		for (auto &i : p.ns.mount.mounts) {
			if (i.type == Mount::Type::BIND && i.IsSourcePath(home))
				i.writable = false;
		}
	}

	// TODO use a proper process name
	child = spawn_service.SpawnChildProcess("foo", std::move(p));
	child->SetExitListener(*this);
}

bool
SessionChannel::Exec(const char *cmd)
{
	const auto &c = static_cast<Connection &>(GetConnection());
	if (!c.IsExecAllowed())
		return false;

	FdHolder close_fds;
	PreparedChildProcess p;

	PrepareChildProcess(p, close_fds, false);

	const char *const shell = c.GetShell();

	if (!c.GetAuthorizedKeyOptions().command.empty()) {
		if (cmd != nullptr)
			p.SetEnv("SSH_ORIGINAL_COMMAND"sv, cmd);

		cmd = c.GetAuthorizedKeyOptions().command.c_str();
	}

	std::string login_shell_name;

	if (cmd != nullptr) {
		p.args.push_back(shell);
		p.args.push_back("-c");
		p.args.push_back(cmd);
	} else {
		p.exec_path = shell;
		p.args.push_back((login_shell_name = LoginShellName(shell)).c_str());
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

Co::EagerTask<bool>
SessionChannel::OnRequest(std::string_view request_type,
			  std::span<const std::byte> type_specific)
{
	const auto &c = static_cast<Connection &>(GetConnection());

	logger.Fmt(1, "ChannelRequest {:?}"sv, request_type);

	if (WasStarted())
		/* the program was already started, and there's no
		   point in handling further requests */
		co_return false;

	if (request_type == "exec"sv) {
		SSH::Deserializer d{type_specific};
		const std::string command{d.ReadString()};
		d.ExpectEnd();

		logger.Fmt(1, "  exec {:?}"sv, command);

		/* throttle if the spawner is under pressure */
		co_await CoEnqueueSpawner(c.GetSpawnService());

		try {
			fmt::print(stderr, "Exec1\n");
			if (!Exec(command.c_str()))
				co_return false;

			co_await CoWaitSpawnCompletion{*child};
			fmt::print(stderr, "Exec2\n");
			co_return true;
		} catch (...) {
			fmt::print(stderr, "Exec3\n");
			logger.Fmt(1, "Failed to spawn child process: {}", std::current_exception());
			co_return false;
		}
	} else if (request_type == "shell"sv) {
		/* throttle if the spawner is under pressure */
		co_await CoEnqueueSpawner(c.GetSpawnService());

		try {
			if (!Exec(nullptr))
				co_return false;

			co_await CoWaitSpawnCompletion{*child};
			co_return true;
		} catch (...) {
			logger.Fmt(1, "Failed to spawn shell: {}", std::current_exception());
			co_return false;
		}
	} else if (request_type == "subsystem"sv) {
		SSH::Deserializer d{type_specific};
		const std::string_view subsystem_name{d.ReadString()};
		d.ExpectEnd();

		logger.Fmt(1, "  subsystem {:?}"sv, subsystem_name);

		if (subsystem_name == "sftp"sv) {
			// TODO repeat translation request with service="sftp"

			if (tty.IsDefined())
				/* refuse to run sftp with a pty */
				co_return false;

			/* throttle if the spawner is under pressure */
			co_await CoEnqueueSpawner(c.GetSpawnService());

			UniqueFileDescriptor sftp_server;
			(void)sftp_server.OpenReadOnly("/usr/lib/cm4all/openssh/libexec/sftp-server");

			FdHolder close_fds;
			PreparedChildProcess p;

			PrepareChildProcess(p, close_fds,
					    sftp_server.IsDefined());

			if (sftp_server.IsDefined()) {
				p.exec_fd = sftp_server;
				p.Append("sftp-server");
			} else
				p.Append("/usr/lib/openssh/sftp-server");

			try {
				SpawnChildProcess(std::move(p));
				co_await CoWaitSpawnCompletion{*child};
				co_return true;
			} catch (...) {
				logger.Fmt(1, "Failed to spawn sftp server: {}", std::current_exception());
				co_return false;
			}
		} else
			co_return false;
	} else if (request_type == "pty-req"sv) {
		if (c.GetAuthorizedKeyOptions().no_pty)
			co_return false;

		struct winsize ws{};

		SSH::Deserializer d{type_specific};
		const auto term = d.ReadString();
		ws.ws_col = d.ReadU32();
		ws.ws_row = d.ReadU32();
		ws.ws_xpixel = d.ReadU32();
		ws.ws_ypixel = d.ReadU32();
		const auto encoded_terminal_modes = d.ReadLengthEncoded();
		d.ExpectEnd();

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

		co_return true;
	} else if (request_type == "env"sv) {
		SSH::Deserializer d{type_specific};
		const auto name = d.ReadString();
		const auto value = d.ReadString();
		d.ExpectEnd();

		SetEnv(name, value);
		co_return true;
	} else
		co_return false;

	// TOOD "signal"
}

void
SessionChannel::OnWriteBlocked() noexcept
{
	if (GetSendWindow() > 0)
		CancelRead();
}

void
SessionChannel::OnWriteUnblocked() noexcept
{
	if (GetSendWindow() > 0)
		ScheduleRead();
}

void
SessionChannel::OnTtyReady([[maybe_unused]] unsigned events) noexcept
try {
	if (events == PipeEvent::HANGUP) {
		tty.Close();
		MaybeSendEofAndClose();
		return;
	}

	if (events & PipeEvent::WRITE) {
		tty.CancelWrite();
		ReadBuffer();
	}

	if ((events & PipeEvent::READ) == 0)
		return;

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
		MaybeSendEofAndClose();
	}
} catch (...) {
	GetConnection().CloseError(std::current_exception());
}

void
SessionChannel::OnStdinReady([[maybe_unused]] unsigned events) noexcept
try {
	stdin_pipe.Cancel();

	ReadBuffer();
} catch (...) {
	GetConnection().CloseError(std::current_exception());
}

void
SessionChannel::OnStdoutReady([[maybe_unused]] unsigned events) noexcept
try {
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
		MaybeSendEofAndClose();
	}
} catch (...) {
	GetConnection().CloseError(std::current_exception());
}

void
SessionChannel::OnStderrReady([[maybe_unused]] unsigned events) noexcept
try {
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
		MaybeSendEofAndClose();
	}
} catch (...) {
	GetConnection().CloseError(std::current_exception());
}

void
SessionChannel::OnChildProcessExit(int status) noexcept
try {
	child = {};
	stdin_pipe.Close();

	if (WIFSIGNALED(status)) {
		const char *signal_name = sigdescr_np(WTERMSIG(status));

		SendExitSignal(signal_name != nullptr ? signal_name : "UNKNOWN",
			       WCOREDUMP(status),
			       {});
	} else {
		SendExitStatus(WEXITSTATUS(status));
	}

	CloseIfInactive();
} catch (...) {
	GetConnection().CloseError(std::current_exception());
}
