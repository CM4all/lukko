// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "LoginGlue.hxx"
#include "LoginClient.hxx"
#include "translation/Response.hxx"
#include "AllocatorPtr.hxx"
#include "net/SocketError.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "net/AllocatedSocketAddress.hxx"

#include <sys/socket.h>

TranslateResponse
TranslateLogin(AllocatorPtr alloc, const char *socket_path,
	       std::string_view service, std::string_view listener_tag,
	       std::string_view user, std::string_view password)
{
	UniqueSocketDescriptor fd;
	if (!fd.Create(AF_LOCAL, SOCK_STREAM, 0))
		throw MakeSocketError("Failed to create translation socket");

	{
		AllocatedSocketAddress address;
		address.SetLocal(socket_path);

		if (!fd.Connect(address))
			throw MakeSocketError("Failed to connect to translation server");
	}

	return TranslateLogin(alloc, fd,
			      service, listener_tag,
			      user, password);
}
