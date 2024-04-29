// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "LoginGlue.hxx"
#include "LoginClient.hxx"
#include "translation/Response.hxx"
#include "AllocatorPtr.hxx"
#include "net/LocalSocketAddress.hxx"
#include "net/SocketError.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "co/Task.hxx"

#include <sys/socket.h>

Co::Task<TranslateResponse>
TranslateLogin(EventLoop &event_loop,
	       AllocatorPtr alloc, const char *socket_path,
	       std::string_view service, std::string_view listener_tag,
	       std::string_view user, std::string_view password)
{
	UniqueSocketDescriptor fd;
	if (!fd.Create(AF_LOCAL, SOCK_STREAM, 0))
		throw MakeSocketError("Failed to create translation socket");

	if (!fd.Connect(LocalSocketAddress{socket_path}))
		throw MakeSocketError("Failed to connect to translation server");

	return TranslateLogin(event_loop, alloc, std::move(fd),
			      service, listener_tag,
			      user, password);
}
