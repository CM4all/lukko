// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Digest.hxx"

#include <openssl/evp.h>

#include <cstddef>
#include <span>

bool
VerifyGeneric(EVP_PKEY &key, DigestAlgorithm hash_alg,
	      std::span<const std::byte> message,
	      std::span<const std::byte> signature);
