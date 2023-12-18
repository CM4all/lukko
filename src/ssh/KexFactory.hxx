// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "config.h"

#include <memory>
#include <string_view>

namespace SSH {

class Kex;

static constexpr std::string_view all_kex_algorithms =
	"curve25519-sha256"
#ifdef HAVE_OPENSSL
	",ecdh-sha2-nistp256"
#endif
	"";

/**
 * Returns nullptr if #algorithms contains no supported algorithm.
 */
std::unique_ptr<Kex>
MakeKex(std::string_view algorithms) noexcept;

} // namespace SSH
