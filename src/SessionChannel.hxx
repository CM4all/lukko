// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "ssh/Channel.hxx"
#include "spawn/ExitListener.hxx"
#include "event/PipeEvent.hxx"
#include "io/UniqueFileDescriptor.hxx"

#include <forward_list>
#include <memory>

struct PreparedChildProcess;
class SpawnService;
class ChildProcessHandle;

class SessionChannel final : public SSH::Channel, ExitListener
{
	static constexpr std::size_t RECEIVE_WINDOW = 16384;

	SpawnService &spawn_service;

	std::unique_ptr<ChildProcessHandle> child;

	UniqueFileDescriptor stdin_pipe, slave_tty;

	PipeEvent stdout_pipe, stderr_pipe, tty;

	/**
	 * Environment variables for the new process: a linked list of
	 * "NAME=VALUE" strings.
	 */
	std::forward_list<std::string> env;

public:
	SessionChannel(SpawnService &_spawn_service,
		       SSH::CConnection &_connection,
		       SSH::ChannelInit init) noexcept;

	~SessionChannel() noexcept override;

	/* virtual methods from class SSH::Channel */
	void OnWindowAdjust(std::size_t nbytes) override;
	void OnData(std::span<const std::byte> payload) override;
	void OnEof() override;
	bool OnRequest(std::string_view request_type,
		       std::span<const std::byte> type_specific) override;

private:
	bool WasStarted() const noexcept {
		return child != nullptr;
	}

	bool IsActive() const noexcept {
		return stdin_pipe.IsDefined() ||
			stdout_pipe.IsDefined() || stderr_pipe.IsDefined() ||
			tty.IsDefined() ||
			child;
	}

	void CloseIfInactive() noexcept;

	void SetEnv(std::string_view name, std::string_view value) noexcept;

	void PrepareChildProcess(PreparedChildProcess &p);
	void SpawnChildProcess(PreparedChildProcess &&p);
	void Exec(const char *cmd);

	void CancelRead() noexcept {
		stdout_pipe.CancelRead();
		stderr_pipe.CancelRead();
		tty.CancelRead();
	}

	void ScheduleRead() noexcept {
		if (stdout_pipe.IsDefined())
			stdout_pipe.ScheduleRead();
		if (stderr_pipe.IsDefined())
			stderr_pipe.ScheduleRead();
		if (tty.IsDefined())
			tty.ScheduleRead();
	}

	void OnTtyReady(unsigned events) noexcept;
	void OnStdoutReady(unsigned events) noexcept;
	void OnStderrReady(unsigned events) noexcept;

	/* virtual methods from class ExitListener */
	void OnChildProcessExit(int status) noexcept override;
};
