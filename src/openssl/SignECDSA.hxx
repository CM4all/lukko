// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <openssl/evp.h>

#include <cstddef>
#include <span>

namespace SSH { class Serializer; }

void
SignECDSA(SSH::Serializer &s,
	  EVP_PKEY &key, int ecdsa_nid,
	  std::span<const std::byte> src);
