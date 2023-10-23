// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Connection.hxx"

#include <array>
#include <cstdint>
#include <memory>

namespace SSH {

struct ChannelInit;
class Channel;

/**
 * Add SSH channel support to class #Connection.
 */
class CConnection : public Connection
{
	std::array<Channel *, 64> channels{};

public:
	using Connection::Connection;

	~CConnection() noexcept;

	void CloseChannel(Channel &channel) noexcept;

private:
	uint_least32_t AllocateChannelIndex() noexcept;

	Channel &GetChannel(uint_least32_t local_channel);

	void HandleChannelOpen(std::span<const std::byte> payload);
	void HandleChannelWindowAdjust(std::span<const std::byte> payload);
	void HandleChannelData(std::span<const std::byte> payload);
	void HandleChannelExtendedData(std::span<const std::byte> payload);
	void HandleChannelEof(std::span<const std::byte> payload);
	void HandleChannelClose(std::span<const std::byte> payload);
	void HandleChannelRequest(std::span<const std::byte> payload);

protected:
	virtual std::unique_ptr<Channel> OpenChannel(std::string_view channel_type,
						     ChannelInit _init);

	/* virtual methods from class SSH::Connection */
	void HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload) override;
};

} // namespace SSH
