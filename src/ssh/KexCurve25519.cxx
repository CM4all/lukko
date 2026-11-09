// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "KexCurve25519.hxx"
#include "Curve25519.hxx"
#include "Serializer.hxx"
#include "system/Urandom.hxx"
#include "util/ScopeExit.hxx"

#include <sodium/utils.h>

#include <stdexcept>

namespace SSH {

Curve25519Kex::Curve25519Kex()
{
	UrandomFill(secret_key);
}

Curve25519Kex::~Curve25519Kex() noexcept
{
	sodium_memzero(&secret_key, sizeof(secret_key));
}

void
Curve25519Kex::SerializeEphemeralPublicKey(Serializer &s) const
{
	Curve25519SecretKeyToPublicKey(secret_key, s.WriteN<sizeof(Curve25519)>());
}

void
Curve25519Kex::GenerateSharedSecret(std::span<const std::byte> client_ephemeral_public_key,
				    Serializer &shared_secret)
{
	if (client_ephemeral_public_key.size() != sizeof(Curve25519))
		throw std::invalid_argument{"Wrong size"};

	Curve25519 shared_key;
	AtScopeExit(&shared_key) { sodium_memzero(shared_key.data(), shared_key.size()); };

	Curve25519CalcSharedKey(secret_key,
				client_ephemeral_public_key.first<sizeof(Curve25519)>(),
				shared_key);

	const auto length = shared_secret.PrepareLength();
	shared_secret.WriteBignum2(shared_key);
	shared_secret.CommitLength(length);
}

} // namespace SSH
