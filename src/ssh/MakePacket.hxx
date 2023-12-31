// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "PacketSerializer.hxx"

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
MakeServiceRequest(std::string_view service_name) noexcept
{
	PacketSerializer s{MessageNumber::SERVICE_REQUEST};
	s.WriteString(service_name);
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
MakeUserauthFailure(std::string_view continue_authentications,
		    bool partial_success) noexcept
{
	PacketSerializer s{MessageNumber::USERAUTH_FAILURE};
	s.WriteString(continue_authentications);
	s.WriteBool(partial_success);
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
MakeUserauthPkOk(std::string_view public_key_algorithm,
		 std::span<const std::byte> public_key) noexcept
{
	PacketSerializer s{MessageNumber::USERAUTH_PK_OK};
	s.WriteString(public_key_algorithm);
	s.WriteLengthEncoded(public_key);
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

[[gnu::pure]]
inline PacketSerializer
MakeChannelWindowAdjust(uint_least32_t recipient_channel,
			uint_least32_t nbytes) noexcept
{
	PacketSerializer s{MessageNumber::CHANNEL_WINDOW_ADJUST};
	s.WriteU32(recipient_channel);
	s.WriteU32(nbytes);
	return s;
}

[[gnu::pure]]
inline PacketSerializer
MakeChannelClose(uint_least32_t recipient_channel) noexcept
{
	PacketSerializer s{MessageNumber::CHANNEL_CLOSE};
	s.WriteU32(recipient_channel);
	return s;
}

[[gnu::pure]]
inline PacketSerializer
MakeChannelReqest(uint_least32_t recipient_channel,
		  std::string_view request_type,
		  bool want_reply) noexcept
{
	PacketSerializer s{MessageNumber::CHANNEL_REQUEST};
	s.WriteU32(recipient_channel);
	s.WriteString(request_type);
	s.WriteBool(want_reply);
	return s;
}

} // namespace SSH
