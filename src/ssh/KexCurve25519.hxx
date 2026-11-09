// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "KexInterface.hxx"
#include "lib/sodium/Curve25519Types.hxx"

#include <array>

namespace SSH {

class Serializer;

class Curve25519Kex final : public Kex {
	Curve25519Scalar secret_key;

public:
	Curve25519Kex();
	~Curve25519Kex() noexcept override;

	void SerializeEphemeralPublicKey(Serializer &s) const override;
	void GenerateSharedSecret(std::span<const std::byte> client_ephemeral_public_key,
				  Serializer &s) override;
};

} // namespace SSH
