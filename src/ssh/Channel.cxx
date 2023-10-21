// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Channel.hxx"
#include "CConnection.hxx"
#include "Serializer.hxx"

namespace SSH {

void
Channel::Close() noexcept
{
	connection.CloseChannel(*this);
}

void
Channel::SendData(std::span<const std::byte> src)
{
	PacketSerializer s{MessageNumber::CHANNEL_DATA};
	s.WriteU32(GetPeerChannel());
	s.WriteLengthEncoded(src);
	connection.SendPacket(std::move(s));
}

void
Channel::SendExtendedData(ChannelExtendedDataType data_type,
			  std::span<const std::byte> src)
{
	PacketSerializer s{MessageNumber::CHANNEL_EXTENDED_DATA};
	s.WriteU32(GetPeerChannel());
	s.WriteU32(static_cast<uint_least32_t>(data_type));
	s.WriteLengthEncoded(src);
	connection.SendPacket(std::move(s));
}

void
Channel::SendStderr(std::span<const std::byte> src)
{
	SendExtendedData(ChannelExtendedDataType::STDERR, src);
}

void
Channel::SendEof()
{
	PacketSerializer s{MessageNumber::CHANNEL_EOF};
	s.WriteU32(GetPeerChannel());
	connection.SendPacket(std::move(s));
}

void
Channel::SerializeOpenConfirmation([[maybe_unused]] Serializer &s) const
{
}

void
Channel::OnData([[maybe_unused]] std::span<const std::byte> payload)
{
}

bool
Channel::OnRequest([[maybe_unused]] std::string_view request_type,
		   [[maybe_unused]] std::span<const std::byte> type_specific)
{
	return false;
}

} // namespace SSH
