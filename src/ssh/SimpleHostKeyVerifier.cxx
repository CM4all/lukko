// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "SimpleHostKeyVerifier.hxx"
#include "key/Set.hxx"

namespace SSH {

bool
SimpleHostKeyVerifier::VerifyHostKey(std::span<const std::byte> server_host_key_blob) const noexcept
{
	return keys.Contains(server_host_key_blob);
}

} // namespace SSH
