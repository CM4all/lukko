// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "LoginGlue.hxx"
#include "LoginClient.hxx"
#include "translation/Response.hxx"
#include "AllocatorPtr.hxx"
#include "net/ConnectSocket.hxx"
#include "net/LocalSocketAddress.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "co/Task.hxx"

#include <sys/socket.h>

Co::Task<TranslateResponse>
TranslateLogin(EventLoop &event_loop,
	       AllocatorPtr alloc, const char *socket_path,
	       std::string_view service, std::string_view listener_tag,
	       std::string_view user, std::string_view password,
	       bool peek)
{
	auto fd = CreateConnectSocket(LocalSocketAddress{socket_path}, SOCK_STREAM);
	return TranslateLogin(event_loop, alloc, std::move(fd),
			      service, listener_tag,
			      user, password, peek);
}
