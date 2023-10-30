// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "RConnect.hxx"
#include "net/RConnectSocket.hxx"
#include "net/UniqueSocketDescriptor.hxx"

#include <string>

UniqueSocketDescriptor
ResolveConnectTCP(std::string_view host, unsigned port)
{
	return ResolveConnectStreamSocket(std::string{host}.c_str(), port,
					  std::chrono::seconds{5});
}
