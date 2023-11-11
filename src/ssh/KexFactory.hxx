// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "config.h"

#include <cstdint>
#include <string_view>

namespace SSH {

static constexpr std::string_view all_kex_algorithms =
	"curve25519-sha256"
#ifdef HAVE_OPENSSL
	",ecdh-sha2-nistp256"
#endif
	"";

enum class KexAlgorithm : uint_least8_t {
	CURVE25519_SHA256,
#ifdef HAVE_OPENSSL
	ECDH_SHA256_NISTP256,
#endif
};

struct NoSupportedKexAlgorithm {};

/**
 * Throws #NoSupportedKexAlgorithm on error.
 */
KexAlgorithm
ChooseKexAlgorithm(std::string_view algorithms);

} // namespace SSH
