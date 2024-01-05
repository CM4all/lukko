// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <string_view>

namespace Co { template<typename> class Task; }
class UniqueSocketDescriptor;
class Connection;

[[nodiscard]]
Co::Task<UniqueSocketDescriptor>
ResolveConnectTCP(const Connection &ssh_connection,
		  std::string_view host, unsigned port) noexcept;
