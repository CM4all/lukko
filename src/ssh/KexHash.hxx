// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Digest.hxx"

#include <cstddef>
#include <span>
#include <string_view>

namespace SSH {

std::size_t
CalcKexHash(DigestAlgorithm hash_alg,
	    std::string_view client_version,
	    std::string_view server_version,
	    std::span<const std::byte> client_kexinit,
	    std::span<const std::byte> server_kexinit,
	    std::span<const std::byte> server_host_key_blob,
	    std::span<const std::byte> client_ephemeral_public_key,
	    std::span<const std::byte> server_ephemeral_public_key,
	    std::span<const std::byte> shared_secret,
	    std::byte *hash);

} // namespace SSH
