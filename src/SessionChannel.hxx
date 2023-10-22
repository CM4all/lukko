// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "ssh/Channel.hxx"
#include "spawn/ExitListener.hxx"
#include "event/PipeEvent.hxx"
#include "io/UniqueFileDescriptor.hxx"

#include <memory>

class SpawnService;
class ChildProcessHandle;

class SessionChannel final : public SSH::Channel, ExitListener
{
	SpawnService &spawn_service;

	std::unique_ptr<ChildProcessHandle> child;

	UniqueFileDescriptor stdin_pipe, slave_tty;

	PipeEvent stdout_pipe, stderr_pipe, tty;

public:
	SessionChannel(SpawnService &_spawn_service,
		       SSH::CConnection &_connection,
		       uint_least32_t _local_channel, uint_least32_t _peer_channel) noexcept;

	~SessionChannel() noexcept override;

	/* virtual methods from class SSH::Channel */
	void OnData(std::span<const std::byte> payload) override;
	void OnEof() override;
	bool OnRequest(std::string_view request_type,
		       std::span<const std::byte> type_specific) override;

private:
	void Exec(const char *cmd);

	void OnTtyReady(unsigned events) noexcept;
	void OnStdoutReady(unsigned events) noexcept;
	void OnStderrReady(unsigned events) noexcept;

	/* virtual methods from class ExitListener */
	void OnChildProcessExit(int status) noexcept override;
};
