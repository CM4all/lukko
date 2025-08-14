// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "event/CoarseTimerEvent.hxx"
#include "event/SocketEvent.hxx"
#include "net/AllocatedSocketAddress.hxx"
#include "net/ClientAccounting.hxx"
#include "io/Logger.hxx"
#include "util/IntrusiveList.hxx"

class Instance;
class Listener;
class UniqueSocketDescriptor;

/**
 * Holds a connection that is delayed (with the "tarpit" option) until
 * the delay expires (or until the client disconnects).
 */
class DelayedConnection final
	: public AutoUnlinkIntrusiveListHook
{
	Instance &instance;
	Listener &listener;

	const AllocatedSocketAddress peer_address;

	const Logger logger;

	AccountedClientConnection accounting;

	CoarseTimerEvent timer;
	SocketEvent socket;

public:
	DelayedConnection(Instance &_instance, Listener &_listener,
			  PerClientAccounting &per_client,
			  Event::Duration delay,
			  UniqueSocketDescriptor fd, SocketAddress _peer_address) noexcept;
	~DelayedConnection() noexcept;

protected:
	void Destroy() noexcept {
		delete this;
	}

private:
	void OnTimer() noexcept;
	void OnSocketReady(unsigned events) noexcept;
};
