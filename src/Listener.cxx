// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Listener.hxx"
#include "Instance.hxx"
#include "Config.hxx"
#include "net/SocketAddress.hxx"

#include <sys/socket.h>

Listener::Listener(Instance &_instance, const ListenerConfig &config)
	:ServerSocket(_instance.GetEventLoop(), config.Create(SOCK_STREAM)),
	 instance(_instance),
#ifdef ENABLE_TRANSLATION
	 tag(config.tag.empty() ? std::string_view{} : config.tag),
#endif
	 proxy_to(config.proxy_to),
	 logger(instance.GetLogger()) {}

void
Listener::OnAccept(UniqueSocketDescriptor connection_fd,
		   SocketAddress peer_address) noexcept
{
	instance.AddConnection(*this, std::move(connection_fd), peer_address);
}

void
Listener::OnAcceptError(std::exception_ptr ep) noexcept
{
	logger(1, "TCP accept error: ", ep);
}
