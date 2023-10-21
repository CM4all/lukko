// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SessionChannel.hxx"
#include "ssh/Deserializer.hxx"
#include "ssh/CConnection.hxx"
#include "system/Error.hxx"

#include <fmt/core.h>

#include <pty.h> // for openpty()
#include <unistd.h>
#include <utmp.h> // for login_tty()

using std::string_view_literals::operator""sv;

SessionChannel::SessionChannel(SSH::CConnection &_connection,
			       uint_least32_t _local_channel, uint_least32_t _peer_channel) noexcept
	:SSH::Channel(_connection, _local_channel, _peer_channel),
	 stdout_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStdoutReady)),
	 stderr_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStderrReady)),
	 tty(_connection.GetEventLoop(), BIND_THIS_METHOD(OnTtyReady))
{
}

SessionChannel::~SessionChannel() noexcept
{
	stdout_pipe.Close();
	stderr_pipe.Close();
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

struct ExecPipes {
	UniqueFileDescriptor stdin, stdout, stderr;
};

static ExecPipes
Execute(const char *command, FileDescriptor tty)
{
	ExecPipes p;

	UniqueFileDescriptor stdin_r, stdout_w, stderr_w;

	if (!tty.IsDefined() &&
	    (!UniqueFileDescriptor::CreatePipe(stdin_r, p.stdin) ||
	     !UniqueFileDescriptor::CreatePipe(p.stdout, stdout_w) ||
	     !UniqueFileDescriptor::CreatePipe(p.stderr, stderr_w)))
		throw MakeErrno("Failed to create pipe");

	const auto pid = fork();
	if (pid < 0)
		throw MakeErrno("Failed to fork");

	if (pid == 0) {
		if (tty.IsDefined()) {
			login_tty(tty.Get());
		} else {
			stdin_r.CheckDuplicate(FileDescriptor{STDIN_FILENO});
			stdout_w.CheckDuplicate(FileDescriptor{STDOUT_FILENO});
			stderr_w.CheckDuplicate(FileDescriptor{STDERR_FILENO});
		}

		if (command != nullptr) {
			const char *const args[] = {
				"sh", "-c", command, nullptr
			};

			execvp("/bin/sh", const_cast<char **>(args));
		} else {
			const char *const args[] = {
				"bash", "-", nullptr
			};

			execvp("/bin/bash", const_cast<char **>(args));
		}

		perror("Failed to execute");
		_exit(EXIT_FAILURE);
	}

	return p;
}

void
SessionChannel::Exec(const char *cmd)
{
	stdout_pipe.Close();
	stderr_pipe.Close();

	auto p = Execute(cmd, slave_tty);
	slave_tty.Close();

	if (tty.IsDefined()) {
		tty.ScheduleRead();
	} else {
		stdin_pipe = std::move(p.stdin);
		stdout_pipe.Open(p.stdout.Release());
		stdout_pipe.ScheduleRead();
		stderr_pipe.Open(p.stderr.Release());
		stderr_pipe.ScheduleRead();
	}
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
	} else
		return false;
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
