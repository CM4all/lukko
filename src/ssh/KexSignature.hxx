// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <cstddef>
#include <span>

namespace SSH {

/**
 * Parse the server host key blob from a KEX reply and verify the
 * signature over the exchange hash.
 *
 * Throws on error (e.g. protocol error).
 *
 * @return true if the signature matches this key, false on
 * mismatch
 */
bool
VerifyKexSignature(std::span<const std::byte> server_host_key_blob,
		   std::span<const std::byte> hash,
		   std::span<const std::byte> signature);

} // namespace SSH
