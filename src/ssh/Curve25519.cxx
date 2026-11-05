// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "Curve25519.hxx"

#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/utils.h>

#include <stdexcept>

static_assert(CURVE25519_SECRET_KEY_SIZE == crypto_scalarmult_curve25519_SCALARBYTES);
static_assert(CURVE25519_PUBLIC_KEY_SIZE == crypto_scalarmult_curve25519_BYTES);
static_assert(CURVE25519_SHARED_KEY_SIZE == crypto_scalarmult_curve25519_BYTES);

void
Curve25519SecretKeyToPublicKey(std::span<const std::byte, CURVE25519_SECRET_KEY_SIZE> key,
			       std::span<std::byte, CURVE25519_PUBLIC_KEY_SIZE> pub)
{
	if (crypto_scalarmult_curve25519_base(reinterpret_cast<unsigned char *>(pub.data()),
					      reinterpret_cast<const unsigned char *>(key.data())) != 0)
		throw std::runtime_error{"crypto_scalarmult_curve25519_base() failed"};
}

void
Curve25519CalcSharedKey(std::span<const std::byte, CURVE25519_SECRET_KEY_SIZE> key,
			std::span<const std::byte, CURVE25519_PUBLIC_KEY_SIZE> pub,
			std::span<std::byte, CURVE25519_SHARED_KEY_SIZE> shared_key)
{
	if (crypto_scalarmult_curve25519(reinterpret_cast<unsigned char *>(shared_key.data()),
					 reinterpret_cast<const unsigned char *>(key.data()),
					 reinterpret_cast<const unsigned char *>(pub.data())) != 0)
		throw std::runtime_error{"crypto_scalarmult_curve25519() failed"};

	/* Check for all-zero shared secret */
	if (sodium_is_zero(reinterpret_cast<const unsigned char *>(shared_key.data()),
			   shared_key.size()))
		throw std::invalid_argument{"Invalid EC value"};
}
