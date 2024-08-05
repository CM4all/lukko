// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "EarlyDisconnect.hxx"
#include "IdentificationString.hxx"
#include "MakePacket.hxx"
#include "net/SocketDescriptor.hxx"
#include "io/Iovec.hxx"
#include "util/SpanCast.hxx"

namespace SSH {

void
SendEarlyDisconnect(SocketDescriptor socket,
		    DisconnectReasonCode reason_code, std::string_view msg) noexcept
{
	auto disconnect_packet = MakeDisconnect(reason_code, msg);
	const struct iovec v[] = {
		MakeIovec(AsBytes(IDENTIFICATION_STRING)),
		MakeIovec(disconnect_packet.Finish(8, false)),
	};

	(void)socket.Send(v);

	/* shut down the socket gracefully so pending data really gets
           transmitted */
	socket.Shutdown();
}

} // namespace SSH
