// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Serializer.hxx"

namespace SSH {

using std::string_view_literals::operator""sv;

[[gnu::pure]]
inline PacketSerializer
MakeDisconnect(DisconnectReasonCode reason_code, std::string_view msg) noexcept
{
	PacketSerializer s{MessageNumber::DISCONNECT};
	s.WriteU32(static_cast<uint32_t>(reason_code));
	s.WriteString(msg);
	s.WriteString("en"sv);
	return s;
}

[[gnu::pure]]
inline PacketSerializer
MakeUnimplemented(uint_least32_t seq) noexcept
{
	PacketSerializer s{MessageNumber::UNIMPLEMENTED};
	s.WriteU32(seq);
	return s;
}

[[gnu::pure]]
inline PacketSerializer
MakeServiceAccept(std::string_view service_name) noexcept
{
	PacketSerializer s{MessageNumber::SERVICE_ACCEPT};
	s.WriteString(service_name);
	return s;
}

[[gnu::pure]]
inline PacketSerializer
MakeUserauthBanner(std::string_view msg) noexcept
{
	PacketSerializer s{MessageNumber::USERAUTH_BANNER};
	s.WriteString(msg);
	s.WriteString("en"sv);
	return s;
}

[[gnu::pure]]
inline PacketSerializer
MakeChannelOpenConfirmation(uint_least32_t recipient_channel,
			    uint_least32_t sender_channel,
			    uint_least32_t initial_window_size,
			    uint_least32_t max_packet_size) noexcept
{
	PacketSerializer s{MessageNumber::CHANNEL_OPEN_CONFIRMATION};
	s.WriteU32(recipient_channel);
	s.WriteU32(sender_channel);
	s.WriteU32(initial_window_size);
	s.WriteU32(max_packet_size);
	return s;
}

[[gnu::pure]]
inline PacketSerializer
MakeChannelOpenFailure(uint_least32_t recipient_channel,
		       ChannelOpenFailureReasonCode reason_code,
		       std::string_view description) noexcept
{
	PacketSerializer s{MessageNumber::CHANNEL_OPEN_FAILURE};
	s.WriteU32(recipient_channel);
	s.WriteU32(static_cast<uint32_t>(reason_code));
	s.WriteString(description);
	s.WriteString("en"sv);
	return s;
}

} // namespace SSH
