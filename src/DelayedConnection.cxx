// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "DelayedConnection.hxx"
#include "Connection.hxx"
#include "Instance.hxx"
#include "Listener.hxx"

using std::string_view_literals::operator""sv;

DelayedConnection::DelayedConnection(Instance &_instance, Listener &_listener,
				     PerClientAccounting &per_client,
				     Event::Duration delay,
				     UniqueSocketDescriptor fd,
				     SocketAddress _peer_address) noexcept
	:instance(_instance), listener(_listener),
	 peer_address(_peer_address),
	 timer(_instance.GetEventLoop(), BIND_THIS_METHOD(OnTimer)),
	 socket(_instance.GetEventLoop(), BIND_THIS_METHOD(OnSocketReady), fd.Release())
{
	per_client.AddConnection(accounting);

	timer.Schedule(delay);

	/* schedule just EPOLLRDHUP because it can reliably detect
	   hangups without having to poll for EPOLLIN */
	socket.Schedule(EPOLLRDHUP);
}

DelayedConnection::~DelayedConnection() noexcept
{
	socket.Close();
}

void
DelayedConnection::OnTimer() noexcept
{
	UniqueSocketDescriptor fd{socket.ReleaseSocket()};

	try {
		auto *c = new Connection(instance, listener,
					 accounting.GetPerClient(),
					 std::move(fd), peer_address);
		listener.connections.push_back(*c);
	} catch (...) {
		logger(1, std::current_exception());
	}

	Destroy();
}

void
DelayedConnection::OnSocketReady([[maybe_unused]] unsigned events) noexcept
{
	/* client has disconnected */
	Destroy();
}
