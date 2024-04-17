// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Listener.hxx"
#include "Instance.hxx"
#include "Config.hxx"
#include "Connection.hxx"
#include "lib/fmt/SocketAddressFormatter.hxx"
#include "net/ClientAccounting.hxx"
#include "net/SocketAddress.hxx"
#include "util/DeleteDisposer.hxx"
#include "config.h"

#include <sys/socket.h>

Listener::Listener(Instance &_instance, const ListenerConfig &config)
	:ServerSocket(_instance.GetEventLoop(), config.Create(SOCK_STREAM)),
	 instance(_instance),
#ifdef ENABLE_TRANSLATION
	 tag(config.tag.empty() ? std::string_view{} : config.tag),
#endif
	 proxy_to(config.proxy_to),
	 logger(instance.GetLogger())
{
	if (config.max_connections_per_ip > 0)
		client_accounting = std::make_unique<ClientAccountingMap>(_instance.GetEventLoop(),
									  config.max_connections_per_ip);
}

Listener::~Listener() noexcept
{
	connections.clear_and_dispose(DeleteDisposer{});
}

void
Listener::OnAccept(UniqueSocketDescriptor connection_fd,
		   SocketAddress peer_address) noexcept
{
	PerClientAccounting *const per_client = client_accounting
		? client_accounting->Get(peer_address)
		: nullptr;
	if (per_client != nullptr) {
		if (!per_client->Check()) {
			/* too many connections from this IP address -
			   reject the new connection */
			// TODO send SSH::DisconnectReasonCode::TOO_MANY_CONNECTIONS
			logger.Fmt(1, "Too many connections from {}", peer_address);
			return;
		}
	}

	try {
		auto *c = new Connection(instance, *this,
					 per_client,
					 std::move(connection_fd), peer_address);
		connections.push_front(*c);
	} catch (...) {
		logger(1, std::current_exception());
	}
}

void
Listener::OnAcceptError(std::exception_ptr ep) noexcept
{
	logger(1, "TCP accept error: ", ep);
}

#ifdef ENABLE_TRANSLATION

void
Listener::TerminateChildren(std::string_view child_tag) noexcept
{
	connections.remove_and_dispose_if([child_tag](const Connection &c){
		return c.HasTag(child_tag);
	}, [](Connection *c){
		c->Terminate();
	});
}

#endif
