// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "ssh/Channel.hxx"
#include "spawn/ExitListener.hxx"
#include "event/PipeEvent.hxx"
#include "io/UniqueFileDescriptor.hxx"
#include "config.h"

#include <forward_list>
#include <memory>

class SpawnService;
class ChildProcessHandle;

class SessionChannel final : public SSH::Channel, ExitListener
{
	SpawnService &spawn_service;

#ifdef ENABLE_TRANSLATION
	const char *const translation_server;
	const std::string_view listener_tag;
#endif

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
#ifdef ENABLE_TRANSLATION
		       const char *_translation_server,
		       std::string_view _listener_tag,
#endif
		       SSH::CConnection &_connection,
		       uint_least32_t _local_channel, uint_least32_t _peer_channel) noexcept;

	~SessionChannel() noexcept override;

	/* virtual methods from class SSH::Channel */
	void OnData(std::span<const std::byte> payload) override;
	void OnEof() override;
	bool OnRequest(std::string_view request_type,
		       std::span<const std::byte> type_specific) override;

private:
	bool IsActive() const noexcept {
		return stdin_pipe.IsDefined() ||
			stdout_pipe.IsDefined() || stderr_pipe.IsDefined() ||
			tty.IsDefined() ||
			child;
	}

	void CloseIfInactive() noexcept;

	void SetEnv(std::string_view name, std::string_view value) noexcept;

	void Exec(const char *cmd);

	void OnTtyReady(unsigned events) noexcept;
	void OnStdoutReady(unsigned events) noexcept;
	void OnStderrReady(unsigned events) noexcept;

	/* virtual methods from class ExitListener */
	void OnChildProcessExit(int status) noexcept override;
};
