// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <cstdint>
#include <string_view>

class SocketDescriptor;

namespace SSH {

enum class DisconnectReasonCode : uint32_t;

/**
 * Send the SSH protocol version exchange followed by a DISCONNECT
 * packet.  Use this to reject a new connection.
 */
void
SendEarlyDisconnect(SocketDescriptor socket,
		    DisconnectReasonCode reason_code, std::string_view msg) noexcept;

} // namespace SSH
