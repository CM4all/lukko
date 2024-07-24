// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "ssh/BufferedChannel.hxx"
#include "spawn/ExitListener.hxx"
#include "event/PipeEvent.hxx"
#include "io/UniqueFileDescriptor.hxx"

#include <forward_list>
#include <memory>

namespace Co { template<typename T> class Task; }
struct PreparedChildProcess;
class ChildProcessHandle;
class FdHolder;
class Logger;

class SessionChannel final : public SSH::BufferedChannel, ExitListener
{
	static constexpr std::size_t RECEIVE_WINDOW = 1024 * 1024;

	const Logger &logger;

	std::unique_ptr<ChildProcessHandle> child;

	UniqueFileDescriptor slave_tty;

	PipeEvent stdin_pipe, stdout_pipe, stderr_pipe, tty;

	/**
	 * Environment variables for the new process: a linked list of
	 * "NAME=VALUE" strings.
	 */
	std::forward_list<std::string> env;

public:
	SessionChannel(SSH::CConnection &_connection,
		       SSH::ChannelInit init) noexcept;

	~SessionChannel() noexcept override;

	/* virtual methods from class SSH::Channel */
	void OnWindowAdjust(std::size_t nbytes) override;
	Co::EagerTask<bool> OnRequest(std::string_view request_type,
				      std::span<const std::byte> type_specific) override;
	void OnWriteBlocked() noexcept override;
	void OnWriteUnblocked() noexcept override;

	/* virtual methods from class SSH::BufferedChannel */
	std::size_t OnBufferedData(std::span<const std::byte> payload) override;
	void OnBufferedEof() override;

private:
	bool WasStarted() const noexcept {
		return child != nullptr;
	}

	bool IsActive() const noexcept {
		return stdout_pipe.IsDefined() || stderr_pipe.IsDefined() ||
			tty.IsDefined() ||
			child;
	}

	/**
	 * Call SSH::Channel::SendEof() if all data sources have ended.
	 *
	 * @return true if SendEof() was called
	 */
	bool MaybeSendEof() noexcept {
		if (stdout_pipe.IsDefined() || stderr_pipe.IsDefined() || tty.IsDefined())
			return false;

		SendEof();
		return true;
	}

	void CloseIfInactive() noexcept;

	/**
	 * Combination of MaybeSendEof() and CloseIfInactive().
	 */
	void MaybeSendEofAndClose() noexcept {
		if (MaybeSendEof())
			CloseIfInactive();
	}

	void SetEnv(std::string_view name, std::string_view value) noexcept;

	void PrepareChildProcess(PreparedChildProcess &p,
				 FdHolder &close_fds,
				 bool sftp);
	void SpawnChildProcess(PreparedChildProcess &&p);

	[[nodiscard]]
	Co::Task<bool> Exec(const char *cmd);

	void CancelRead() noexcept {
		/* stdout/stderr must be canceled completely to avoid
		   getting HANGUP events which we can't handle; but
		   only cancel reading on a tty because a tty is
		   bidirectional and we may still want to get WRITE
		   events */

		stdout_pipe.Cancel();
		stderr_pipe.Cancel();

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
	void OnStdinReady(unsigned events) noexcept;
	void OnStdoutReady(unsigned events) noexcept;
	void OnStderrReady(unsigned events) noexcept;

	/* virtual methods from class ExitListener */
	void OnChildProcessExit(int status) noexcept override;
};
