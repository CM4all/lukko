// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "config.h"

#include <memory>
#include <string_view>

namespace SSH {

class Kex;

static constexpr std::string_view all_server_kex_algorithms =
	"curve25519-sha256"
#ifdef HAVE_OPENSSL
	",ecdh-sha2-nistp256"
#endif
	",kex-strict-s-v00@openssh.com";

static constexpr std::string_view all_client_kex_algorithms =
	"curve25519-sha256"
#ifdef HAVE_OPENSSL
	",ecdh-sha2-nistp256"
#endif
	",kex-strict-c-v00@openssh.com";

/**
 * Returns nullptr if #algorithms contains no supported algorithm.
 *
 * Throws on error.
 */
std::unique_ptr<Kex>
MakeKex(std::string_view algorithms);

} // namespace SSH
