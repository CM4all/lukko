// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "ssh/Channel.hxx"
#include "event/PipeEvent.hxx"
#include "io/UniqueFileDescriptor.hxx"

class SessionChannel final : public SSH::Channel
{
	UniqueFileDescriptor stdin_pipe;

	PipeEvent stdout_pipe, stderr_pipe;

public:
	SessionChannel(SSH::CConnection &_connection,
		       uint_least32_t _local_channel, uint_least32_t _peer_channel) noexcept;

	~SessionChannel() noexcept override;

	/* virtual methods from class SSH::Channel */
	void OnData(std::span<const std::byte> payload) override;
	void OnEof() override;
	bool OnRequest(std::string_view request_type,
		       std::span<const std::byte> type_specific) override;

private:
	void OnStdoutReady(unsigned events) noexcept;
	void OnStderrReady(unsigned events) noexcept;
};
