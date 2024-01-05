// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "event/net/ServerSocket.hxx"
#include "util/IntrusiveList.hxx"

#include <cstdint>
#include <string>

class Connection;

/**
 * A listener on a socket bound by a "tcpip-forward".
 */
class SocketForwardListener final : public IntrusiveListHook<>, ServerSocket {
	Connection &connection;

	class Factory;
	IntrusiveList<Factory> factories;

	const std::string bind_address;
	const uint_least32_t bind_port;

public:
	SocketForwardListener(Connection &_connection,
			      std::string &&_bind_address,
			      uint_least32_t _bind_port,
			      UniqueSocketDescriptor _socket) noexcept;
	~SocketForwardListener() noexcept;

	bool IsBindAddress(std::string_view address, uint_least32_t port) const noexcept {
		return address == bind_address && port == bind_port;
	}

private:
	/* virtual methods from class ServerSocket */
	void OnAccept(UniqueSocketDescriptor fd,
		      SocketAddress address) noexcept override;
	void OnAcceptError(std::exception_ptr error) noexcept override;
};
