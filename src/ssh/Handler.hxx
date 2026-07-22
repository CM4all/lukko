// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "util/IntrusiveList.hxx"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace SSH {

enum class MessageNumber : uint8_t;

/**
 * Handler class for a #Connection instance.  It may handle incoming
 * packets and gets notified for important connection-level events.
 *
 * Call Connection::AddHandler() to register a handler.  It is
 * unregistered by destructing this object.
 */
class ConnectionHandler {
	friend class Connection;
	AutoUnlinkIntrusiveListHook connection_handler_siblings;

public:
	/**
	 * @return true if the packet has been handled
	 */
	[[nodiscard]]
	virtual bool HandlePacket(MessageNumber msg,
				  std::span<const std::byte> payload) = 0;

	/**
	 * The (kernel) socket buffer is full and no more outgoing packets
	 * should be submitted to SendPacket().
	 *
	 * Writing (of regular non-KEX packets) can also be blocked by
	 * rekeying (after sending KEXINIT on a connection that is
	 * already encrypted).
	 */
	virtual void OnWriteBlocked() noexcept {}

	/**
	 * The (kernel) socket buffer is no longer full and
	 * SendPacket() may be called (but not from inside this
	 * method; this method shall only schedule events to produce
	 * more data).
	 */
	virtual void OnWriteUnblocked() noexcept {}

	/**
	 * Called right before sending a DISCONNECT packet to the
	 * peer.  This may be used for logging (but not for I/O or for
	 * actually disconnecting).
	 */
	virtual void OnDisconnecting() noexcept {}
};

} // namespace SSH
