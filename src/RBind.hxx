// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <string_view>

namespace Co { template<typename> class Task; }
class UniqueSocketDescriptor;
class Connection;

/**
 * Create a socket bound to the specified address/port (but doesn't
 * call listen()).
 */
// TODO support multiple sockets if multiple addresses are bound
[[nodiscard]]
Co::Task<UniqueSocketDescriptor>
ResolveBindTCP(const Connection &ssh_connection,
	       std::string_view host, unsigned port) noexcept;
