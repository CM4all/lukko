// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "version.h"

#include <string_view>

namespace SSH {

/**
 * This software's identification string according to RFC 4253 4.2
 */
static constexpr std::string_view IDENTIFICATION_STRING = "SSH-2.0-Lukko_" VERSION " CM4all\r\n";

} // namespace SSH

