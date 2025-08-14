// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "config.h"

#include <string_view>

constexpr std::string_view all_public_key_algorithms =
	"ssh-ed25519"
#ifdef HAVE_OPENSSL
	",ecdsa-sha2-nistp256"
	",rsa-sha2-256,rsa-sha2-512,ssh-rsa"
#endif // HAVE_OPENSSL
	;
