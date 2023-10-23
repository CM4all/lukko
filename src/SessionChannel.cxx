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
#include "system/Error.hxx"
#include "AllocatorPtr.hxx"

#ifdef ENABLE_TRANSLATION
#include "translation/LoginGlue.hxx"
#include "translation/Response.hxx"
#endif // ENABLE_TRANSLATION

#include <fmt/core.h>

#include <pty.h> // for openpty()
#include <signal.h>
#include <unistd.h>
#include <utmp.h> // for login_tty()

using std::string_view_literals::operator""sv;

SessionChannel::SessionChannel(SpawnService &_spawn_service,
#ifdef ENABLE_TRANSLATION
			       const char *_translation_server,
			       std::string_view _listener_tag,
#endif
			       SSH::CConnection &_connection,
			       uint_least32_t _local_channel, uint_least32_t _peer_channel) noexcept
	:SSH::Channel(_connection, _local_channel, _peer_channel),
	 spawn_service(_spawn_service),
#ifdef ENABLE_TRANSLATION
	 translation_server(_translation_server),
	 listener_tag(_listener_tag),
#endif
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
SessionChannel::SetEnv(std::string_view name, std::string_view value) noexcept
{
	// TODO check if already exists?

	env.emplace_front(fmt::format("{}={}", name, value));
}

void
SessionChannel::OnData(std::span<const std::byte> payload)
{
	if (stdin_pipe.IsDefined())
		stdin_pipe.Write(payload);
	else if (tty.IsDefined())
		tty.GetFileDescriptor().Write(payload);
}

void
SessionChannel::OnEof()
{
	stdin_pipe.Close();
}

void
SessionChannel::Exec(const char *cmd)
{
	Allocator alloc;
	PreparedChildProcess p;

#ifdef ENABLE_TRANSLATION
	if (translation_server != nullptr) {
		const auto &c = static_cast<Connection &>(GetConnection());

		auto response = TranslateLogin(alloc, translation_server,
					       "ssh"sv, listener_tag,
					       c.GetUsername(), {});

		if (response.status != HttpStatus{})
			throw std::runtime_error{"Translation server failed"};

		response.child_options.CopyTo(p);
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

	if (cmd != nullptr) {
		p.args.push_back("/bin/sh");
		p.args.push_back("-c");
		p.args.push_back(cmd);
	} else {
		p.args.push_back("/bin/bash");
		p.args.push_back("-");
	}

	if (tty.IsDefined()) {
		p.stdin_fd = p.stdout_fd = p.stderr_fd = slave_tty.Release();
		p.tty = true;

		tty.ScheduleRead();
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
		stdout_pipe.ScheduleRead();
		stderr_pipe.Open(stderr_r.Release());
		stderr_pipe.ScheduleRead();
	}

	if (const char *mount_home = p.ns.mount.GetMountHome()) {
		p.SetEnv("HOME", mount_home);
		p.chdir = mount_home;
	}

	// TODO use a proper process name
	child = spawn_service.SpawnChildProcess("foo", std::move(p));
	child->SetExitListener(*this);
}

bool
SessionChannel::OnRequest(std::string_view request_type,
			  std::span<const std::byte> type_specific)
{
	fmt::print(stderr, "ChannelRequest '{}'\n", request_type);

	if (request_type == "exec"sv) {
		SSH::Deserializer d{type_specific};
		const std::string command{d.ReadString()};
		fmt::print(stderr, "  exec '{}'\n", command);

		Exec(command.c_str());
		return true;
	} else if (request_type == "shell"sv) {
		Exec(nullptr);
		return true;
	} else if (request_type == "pty-req"sv) {
		struct winsize ws{};

		SSH::Deserializer d{type_specific};
		d.ReadString(); // TODO TERM environment variable
		ws.ws_col = d.ReadU32();
		ws.ws_row = d.ReadU32();
		ws.ws_xpixel = d.ReadU32();
		ws.ws_ypixel = d.ReadU32();
		d.ReadString(); // TODO encoded terminal modes

		int master, slave;

		if (openpty(&master, &slave, nullptr, nullptr, &ws) < 0)
			throw MakeErrno("openpty() failed");

		slave_tty = UniqueFileDescriptor{slave};
		slave_tty.EnableCloseOnExec();

		tty.Close();
		tty.Open(FileDescriptor{master});
		tty.GetFileDescriptor().EnableCloseOnExec();

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
	std::byte buffer[4096];
	auto nbytes = tty.GetFileDescriptor().Read(buffer);
	if (nbytes > 0) {
		SendData(std::span{buffer}.first(nbytes));
	} else {
		tty.Close();
		SendEof();
	}
}

void
SessionChannel::OnStdoutReady([[maybe_unused]] unsigned events) noexcept
{
	std::byte buffer[4096];
	auto nbytes = stdout_pipe.GetFileDescriptor().Read(buffer);
	if (nbytes > 0) {
		SendData(std::span{buffer}.first(nbytes));
	} else {
		stdout_pipe.Close();
		SendEof();
	}
}

void
SessionChannel::OnStderrReady([[maybe_unused]] unsigned events) noexcept
{
	std::byte buffer[4096];
	auto nbytes = stderr_pipe.GetFileDescriptor().Read(buffer);
	if (nbytes > 0) {
		SendStderr(std::span{buffer}.first(nbytes));
	} else {
		stderr_pipe.Close();
	}
}

void
SessionChannel::OnChildProcessExit(int status) noexcept
{
	// TODO submit status via "exit-status" or "exit-signal"
	(void)status;

	child = {};

	// TODO flush pending data from pipes?

	Close();
}
