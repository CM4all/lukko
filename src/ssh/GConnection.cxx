// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "GConnection.hxx"
#include "PacketSerializer.hxx"
#include "ParsePacket.hxx"

namespace SSH {

bool
GConnection::HandleGlobalRequest([[maybe_unused]] std::string_view request_name,
				 [[maybe_unused]] std::span<const std::byte> request_specific_data)
{
	return false;
}

inline void
GConnection::HandleGlobalRequest(std::span<const std::byte> payload)
{
	const auto p = ParseGlobalRequest(payload);

	const bool success = HandleGlobalRequest(p.request_name,
						 p.request_specific_data);

	if (p.want_reply)
		SendPacket(PacketSerializer{success
				? MessageNumber::REQUEST_SUCCESS
				: MessageNumber::REQUEST_FAILURE});
}

void
GConnection::HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload)
{
	if (!IsEncrypted() || !IsAuthenticated())
		return Connection::HandlePacket(msg, payload);

	switch (msg) {
	case MessageNumber::GLOBAL_REQUEST:
		HandleGlobalRequest(payload);
		break;

	default:
		Connection::HandlePacket(msg, payload);
	}
}

} // namespace SSH
