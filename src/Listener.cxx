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
	 logger(instance.GetLogger()) {}

void
Listener::OnAccept(UniqueSocketDescriptor &&connection_fd,
		   SocketAddress) noexcept
{
	instance.AddConnection(std::move(connection_fd));
}

void
Listener::OnAcceptError(std::exception_ptr ep) noexcept
{
	logger(1, "TCP accept error: ", ep);
}
