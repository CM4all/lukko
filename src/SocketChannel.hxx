// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "ssh/BufferedChannel.hxx"
#include "event/SocketEvent.hxx"

class UniqueSocketDescriptor;

/**
 * Copy data between a #SocketDescriptor and a SSH channel.
 */
class SocketChannel final : public SSH::BufferedChannel
{
	static constexpr std::size_t RECEIVE_WINDOW = 16384;

	SocketEvent socket;

public:
	SocketChannel(SSH::CConnection &_connection,
		      SSH::ChannelInit init,
		      UniqueSocketDescriptor _socket) noexcept;

	~SocketChannel() noexcept override;

	/* virtual methods from class SSH::Channel */
	void OnWindowAdjust(std::size_t nbytes) override;
	void OnWriteBlocked() noexcept override;
	void OnWriteUnblocked() noexcept override;

	/* virtual methods from class SSH::BufferedChannel */
	std::size_t OnBufferedData(std::span<const std::byte> payload) override;
	void OnBufferedEof() override;

private:
	void OnSocketReady(unsigned events) noexcept;
};
