// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <array>
#include <cstdint>

namespace SSH {

enum class Role : uint_least8_t {
	SERVER,
	CLIENT,
};

enum class Direction : uint_least8_t {
	INCOMING,
	OUTGOING,
};

} // namespace SSH
