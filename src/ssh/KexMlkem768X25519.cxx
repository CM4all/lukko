// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "KexMlkem768X25519.hxx"

#ifdef HAVE_MLKEM768

#include "Curve25519.hxx"
#include "Serializer.hxx"
#include "lib/sodium/SHA256.hxx"
#include "system/Urandom.hxx"
#include "util/ScopeExit.hxx"

#include <sodium/crypto_kem_mlkem768.h>
#include <sodium/utils.h>

#include <stdexcept>

namespace SSH {

static_assert(MLKEM768_PUBLIC_KEY_SIZE == crypto_kem_mlkem768_PUBLICKEYBYTES);
static_assert(MLKEM768_SECRET_KEY_SIZE == crypto_kem_mlkem768_SECRETKEYBYTES);
static_assert(MLKEM768_CIPHERTEXT_SIZE == crypto_kem_mlkem768_CIPHERTEXTBYTES);
static_assert(MLKEM768_SHARED_KEY_SIZE == crypto_kem_mlkem768_SHAREDSECRETBYTES);

static unsigned char *
ToUC(std::byte *p) noexcept
{
	return reinterpret_cast<unsigned char *>(p);
}

static const unsigned char *
ToUC(const std::byte *p) noexcept
{
	return reinterpret_cast<const unsigned char *>(p);
}

Mlkem768X25519Kex::Mlkem768X25519Kex(Role _role)
	:role(_role)
{
	static_assert(sizeof(x25519_secret_key) == CURVE25519_SECRET_KEY_SIZE);

	UrandomFill(x25519_secret_key);

	if (role == Role::CLIENT &&
	    crypto_kem_mlkem768_keypair(ToUC(mlkem_public_key.data()),
					ToUC(mlkem_secret_key.data())) != 0)
		throw std::runtime_error{"crypto_kem_mlkem768_keypair() failed"};
}

Mlkem768X25519Kex::~Mlkem768X25519Kex() noexcept
{
	sodium_memzero(x25519_secret_key.data(), x25519_secret_key.size());
	sodium_memzero(mlkem_secret_key.data(), mlkem_secret_key.size());
}

void
Mlkem768X25519Kex::SerializeEphemeralPublicKey(Serializer &s) const
{
	switch (role) {
	case Role::SERVER:
		s.WriteN(mlkem_ciphertext);
		break;

	case Role::CLIENT:
		s.WriteN(mlkem_public_key);
		break;
	}

	Curve25519SecretKeyToPublicKey(x25519_secret_key,
				       s.WriteN<CURVE25519_PUBLIC_KEY_SIZE>());
}

void
Mlkem768X25519Kex::GenerateSharedSecret(std::span<const std::byte> peer_ephemeral_public_key,
					Serializer &shared_secret)
{
	/* the ML-KEM-768 shared secret followed by the X25519 shared
	   secret; this will be hashed */
	std::array<std::byte, MLKEM768_SHARED_KEY_SIZE + CURVE25519_SHARED_KEY_SIZE> shared_keys;
	AtScopeExit(&shared_keys) { sodium_memzero(shared_keys.data(), shared_keys.size()); };

	const auto mlkem_shared_key = std::span{shared_keys}.first<MLKEM768_SHARED_KEY_SIZE>();
	const auto x25519_shared_key = std::span{shared_keys}.last<CURVE25519_SHARED_KEY_SIZE>();

	switch (role) {
	case Role::SERVER:
		/* the client sends its ML-KEM-768 encapsulation key
		   followed by its X25519 public key */
		if (peer_ephemeral_public_key.size() != MLKEM768_PUBLIC_KEY_SIZE + CURVE25519_PUBLIC_KEY_SIZE)
			throw std::invalid_argument{"Wrong size"};

		/* this fails if the encapsulation key is invalid
		   (FIPS 203 modulus check) */
		if (crypto_kem_mlkem768_enc(ToUC(mlkem_ciphertext.data()),
					    ToUC(mlkem_shared_key.data()),
					    ToUC(peer_ephemeral_public_key.data())) != 0)
			throw std::invalid_argument{"Invalid ML-KEM-768 public key"};

		break;

	case Role::CLIENT:
		/* the server sends the ML-KEM-768 ciphertext followed
		   by its X25519 public key */
		if (peer_ephemeral_public_key.size() != MLKEM768_CIPHERTEXT_SIZE + CURVE25519_PUBLIC_KEY_SIZE)
			throw std::invalid_argument{"Wrong size"};

		if (crypto_kem_mlkem768_dec(ToUC(mlkem_shared_key.data()),
					    ToUC(peer_ephemeral_public_key.data()),
					    ToUC(mlkem_secret_key.data())) != 0)
			throw std::invalid_argument{"Invalid ML-KEM-768 ciphertext"};

		break;
	}

	Curve25519CalcSharedKey(x25519_secret_key,
				peer_ephemeral_public_key.last<CURVE25519_PUBLIC_KEY_SIZE>(),
				x25519_shared_key);

	/* K = SHA-256(K_PQ || K_CL), encoded as "string" (not as
	   "mpint") */
	auto k = SHA256(shared_keys);
	AtScopeExit(&k) { sodium_memzero(k.data(), k.size()); };

	shared_secret.WriteLengthEncoded(k);
}

} // namespace SSH

#endif // HAVE_MLKEM768
