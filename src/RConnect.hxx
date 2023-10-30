// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <string_view>

class UniqueSocketDescriptor;
class Connection;

UniqueSocketDescriptor
ResolveConnectTCP(const Connection &ssh_connection,
		  std::string_view host, unsigned port);
