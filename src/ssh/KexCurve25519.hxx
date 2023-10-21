// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include <cstddef>
#include <span>

namespace SSH {

class Serializer;

void
Curve25519Kex(std::span<const std::byte> client_ephemeral_public_key,
	      Serializer &server_ephemeral_public_key,
	      Serializer &shared_secret);

} // namespace SSH
