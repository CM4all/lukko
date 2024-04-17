// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Listener.hxx"
#include "Instance.hxx"
#include "Config.hxx"
#include "Connection.hxx"
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
	 logger(instance.GetLogger()) {}

Listener::~Listener() noexcept
{
	connections.clear_and_dispose(DeleteDisposer{});
}

void
Listener::OnAccept(UniqueSocketDescriptor connection_fd,
		   SocketAddress peer_address) noexcept
{
	try {
		auto *c = new Connection(instance, *this,
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
