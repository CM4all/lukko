// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <cstddef>

namespace SSH {

static constexpr std::size_t HEADER_SIZE = 4;

static constexpr std::size_t MAX_PACKET_SIZE = 35000;

static constexpr std::size_t KEX_COOKIE_SIZE = 16;

} // namespace SSH
