// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Curve25519Key.hxx"
#include "ssh/Serializer.hxx"
#include "system/Urandom.hxx"

#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/utils.h>

#include <stdexcept>

using std::string_view_literals::operator""sv;

Curve25519Key::~Curve25519Key() noexcept
{
	sodium_memzero(&key, sizeof(key));
}

void
Curve25519Key::Generate()
{
	static_assert(sizeof(key) == crypto_scalarmult_curve25519_SCALARBYTES);
	static_assert(sizeof(pub) == crypto_scalarmult_curve25519_BYTES);

	UrandomFill(key);

	if (crypto_scalarmult_curve25519_base(reinterpret_cast<unsigned char *>(pub.data()),
					      reinterpret_cast<const unsigned char *>(key.data())) != 0)
		throw std::runtime_error{"crypto_scalarmult_curve25519_base() failed"};
}

std::string_view
Curve25519Key::GetAlgorithm() const noexcept
{
	// TODO
	return "curve25519"sv;
}

void
Curve25519Key::SerializePublic(SSH::Serializer &s) const
{
	s.WriteN(pub);
}

void
Curve25519Key::SerializeKex(SSH::Serializer &s) const
{
	// TODO
	(void)s;
}

void
Curve25519Key::Sign(SSH::Serializer &s, std::span<const std::byte> src) const
{
	// TODO
	(void)s;
	(void)src;
}
