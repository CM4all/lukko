// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <span>

namespace SSH {

class Serializer;

class Kex {
public:
	virtual ~Kex() noexcept = default;

	virtual void SerializeEphemeralPublicKey(Serializer &s) const = 0;
	virtual void GenerateSharedSecret(std::span<const std::byte> client_ephemeral_public_key,
					  Serializer &s) = 0;
};

} // namespace SSH
