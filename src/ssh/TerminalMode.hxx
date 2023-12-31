// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <span>

struct termios;

namespace SSH {

void
ParseTerminalModes(struct termios &tio, std::span<const std::byte> src) noexcept;

} // namespace SSH
