// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SessionChannel.hxx"
#include "ssh/Deserializer.hxx"
#include "ssh/CConnection.hxx"
#include "system/Error.hxx"

#include <fmt/core.h>

#include <unistd.h>

using std::string_view_literals::operator""sv;

SessionChannel::SessionChannel(SSH::CConnection &_connection,
			       uint_least32_t _local_channel, uint_least32_t _peer_channel) noexcept
	:SSH::Channel(_connection, _local_channel, _peer_channel),
	 stdout_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStdoutReady)),
	 stderr_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStderrReady))
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
Execute(const char *command)
{
	ExecPipes p;

	UniqueFileDescriptor stdin_r, stdout_w, stderr_w;

	if (!UniqueFileDescriptor::CreatePipe(stdin_r, p.stdin) ||
	    !UniqueFileDescriptor::CreatePipe(p.stdout, stdout_w) ||
	    !UniqueFileDescriptor::CreatePipe(p.stderr, stderr_w))
		throw MakeErrno("Failed to create pipe");

	const auto pid = fork();
	if (pid < 0)
		throw MakeErrno("Failed to fork");

	if (pid == 0) {
		stdin_r.CheckDuplicate(FileDescriptor{STDIN_FILENO});
		stdout_w.CheckDuplicate(FileDescriptor{STDOUT_FILENO});
		stderr_w.CheckDuplicate(FileDescriptor{STDERR_FILENO});

		const char *const args[] = {
			"sh", "-c", command, nullptr
		};

		execvp("/bin/sh", const_cast<char **>(args));
		perror("Failed to execute");
		_exit(EXIT_FAILURE);
	}

	return p;
}

bool
SessionChannel::OnRequest(std::string_view request_type,
			  std::span<const std::byte> type_specific)
{
	fmt::print(stderr, "ChannelRequest '{}'\n", request_type);

	if (request_type == "exec"sv) {
		stdout_pipe.Close();
		stderr_pipe.Close();

		SSH::Deserializer d{type_specific};
		const std::string command{d.ReadString()};
		fmt::print(stderr, "  exec '{}'\n", command);

		auto p = Execute(command.c_str());

		stdin_pipe = std::move(p.stdin);
		stdout_pipe.Open(p.stdout.Release());
		stdout_pipe.ScheduleRead();
		stderr_pipe.Open(p.stderr.Release());
		stderr_pipe.ScheduleRead();

		return true;
	} else
		return false;
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
