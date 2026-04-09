// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "KexSignature.hxx"
#include "key/Key.hxx"
#include "key/Parser.hxx"

namespace SSH {

bool
VerifyKexSignature(std::span<const std::byte> server_host_key_blob,
		   std::span<const std::byte> hash,
		   std::span<const std::byte> signature)
{
	const auto public_key = ParsePublicKeyBlob(server_host_key_blob);
	return public_key->Verify(hash, signature);
}

} // namespace SSH
