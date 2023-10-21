// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace SSH {

enum class ChannelExtendedDataType : uint32_t;
class CConnection;
class Serializer;

class Channel {
	CConnection &connection;

	const uint_least32_t local_channel, peer_channel;

public:
	Channel(CConnection &_connection,
		uint_least32_t _local_channel, uint_least32_t _peer_channel) noexcept
		:connection(_connection),
		 local_channel(_local_channel),
		 peer_channel(_peer_channel) {}

	virtual ~Channel() noexcept = default;

	uint_least32_t GetLocalChannel() const noexcept {
		return local_channel;
	}

	uint_least32_t GetPeerChannel() const noexcept {
		return peer_channel;
	}

	void Close() noexcept;

	void SendData(std::span<const std::byte> src);
	void SendExtendedData(ChannelExtendedDataType data_type,
			      std::span<const std::byte> src);
	void SendStderr(std::span<const std::byte> src);
	void SendEof();

	virtual void SerializeOpenConfirmation(Serializer &s) const;
	virtual void OnData(std::span<const std::byte> payload);
	virtual void OnEof() {}

	[[nodiscard]]
	virtual bool OnRequest(std::string_view request_type,
			       std::span<const std::byte> type_specific);
};

} // namespace SSH
