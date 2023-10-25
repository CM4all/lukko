// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Digest.hxx"

#include <openssl/evp.h>

#include <cstddef>
#include <span>

namespace SSH { class Serializer; }

void
SignECDSA(SSH::Serializer &s,
	  EVP_PKEY &key, DigestAlgorithm hash_alg,
	  std::span<const std::byte> src);
