// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "Curve25519.hxx"
#include "lib/sodium/Curve25519ScalarMult.hxx"

#include <sodium/utils.h>

#include <stdexcept>

void
Curve25519SecretKeyToPublicKey(Curve25519ScalarView key, Curve25519Ptr pub)
{
	if (crypto_scalarmult_curve25519_base(pub, key) != 0)
		throw std::runtime_error{"crypto_scalarmult_curve25519_base() failed"};
}

void
Curve25519CalcSharedKey(Curve25519ScalarView key, Curve25519View pub,
			Curve25519Ptr shared_key)
{
	if (crypto_scalarmult_curve25519(shared_key, key, pub) != 0)
		throw std::runtime_error{"crypto_scalarmult_curve25519() failed"};

	/* Check for all-zero shared secret */
	if (sodium_is_zero(reinterpret_cast<const unsigned char *>(shared_key.data()),
			   shared_key.size()))
		throw std::invalid_argument{"Invalid EC value"};
}
