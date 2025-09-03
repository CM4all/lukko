// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "event/net/ServerSocket.hxx"
#include "net/TempListener.hxx"
#include "util/IntrusiveList.hxx"

class Connection;
class SessionChannel;

/**
 * A listener on a socket bound by an "agent-req".
 */
class AgentForward final : ServerSocket {
	Connection &connection;
	SessionChannel &channel;

	TempListener listener;

	class Factory;
	IntrusiveList<Factory> factories;

public:
	AgentForward(Connection &_connection, SessionChannel &_channel) noexcept;
	~AgentForward() noexcept;

	const char *GetPath() const noexcept {
		return listener.GetPath();
	}

private:
	/* virtual methods from class ServerSocket */
	void OnAccept(UniqueSocketDescriptor fd,
		      SocketAddress address) noexcept override;
	void OnAcceptError(std::exception_ptr error) noexcept override;
};
