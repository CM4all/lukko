// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "KexCurve25519.hxx"
#include "Serializer.hxx"
#include "system/Urandom.hxx"
#include "util/ScopeExit.hxx"

#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/utils.h>

#include <stdexcept>

namespace SSH {

Curve25519Kex::Curve25519Kex()
{
	static_assert(sizeof(secret_key) == crypto_scalarmult_curve25519_SCALARBYTES);

	UrandomFill(secret_key);
}

Curve25519Kex::~Curve25519Kex() noexcept
{
	sodium_memzero(&secret_key, sizeof(secret_key));
}

static void
Curve25519SecretKeyToPublicKey(std::span<const std::byte, crypto_scalarmult_curve25519_SCALARBYTES> key,
			       std::span<std::byte, crypto_scalarmult_curve25519_BYTES> pub)
{
	if (crypto_scalarmult_curve25519_base(reinterpret_cast<unsigned char *>(pub.data()),
					      reinterpret_cast<const unsigned char *>(key.data())) != 0)
		throw std::runtime_error{"crypto_scalarmult_curve25519_base() failed"};
}

static void
KexCurve25519CalcSharedKey(std::span<const std::byte, crypto_scalarmult_curve25519_SCALARBYTES> key,
			   std::span<const std::byte, crypto_scalarmult_curve25519_BYTES> pub,
			   Serializer &out, bool raw)
{
	std::byte shared_key[crypto_scalarmult_curve25519_BYTES]{};

	if (crypto_scalarmult_curve25519(reinterpret_cast<unsigned char *>(shared_key),
					 reinterpret_cast<const unsigned char *>(key.data()),
					 reinterpret_cast<const unsigned char *>(pub.data())) != 0)
		throw std::runtime_error{"crypto_scalarmult_curve25519() failed"};

	AtScopeExit(&shared_key) { sodium_memzero(shared_key, sizeof(shared_key)); };

	/* Check for all-zero shared secret */
	if (sodium_is_zero(reinterpret_cast<const unsigned char *>(shared_key),
			   sizeof(shared_key)))
		throw std::invalid_argument{"Invalid EC value"};

	if (raw)
		out.WriteN(shared_key);
	else
		out.WriteBignum2(shared_key);
}

void
Curve25519Kex::MakeReply(std::span<const std::byte> client_ephemeral_public_key,
			 Serializer &server_ephemeral_public_key,
			 Serializer &shared_secret)
{
	if (client_ephemeral_public_key.size() != crypto_scalarmult_curve25519_BYTES)
		throw std::invalid_argument{"Wrong size"};

	Curve25519SecretKeyToPublicKey(secret_key,
				       server_ephemeral_public_key.WriteN<crypto_scalarmult_curve25519_BYTES>());

	KexCurve25519CalcSharedKey(secret_key,
				   client_ephemeral_public_key.first<crypto_scalarmult_curve25519_BYTES>(),
				   shared_secret, false);
}

} // namespace SSH
