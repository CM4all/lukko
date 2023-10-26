// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Ed25519Key.hxx"
#include "ssh/Serializer.hxx"
#include "system/Urandom.hxx"

#include <sodium/crypto_sign_ed25519.h>
#include <sodium/utils.h>

using std::string_view_literals::operator""sv;

Ed25519Key::Ed25519Key(Generate) noexcept
{
	static_assert(sizeof(public_key) == crypto_sign_ed25519_PUBLICKEYBYTES);
	static_assert(sizeof(secret_key) == crypto_sign_ed25519_SECRETKEYBYTES);

	crypto_sign_ed25519_keypair(reinterpret_cast<unsigned char *>(public_key.data()),
				    reinterpret_cast<unsigned char *>(secret_key.data()));
}

Ed25519Key::Ed25519Key(std::span<const std::byte, 32> _public_key,
		       std::span<const std::byte, 64> _secret_key) noexcept
{
	std::copy(_public_key.begin(), _public_key.end(), public_key.begin());
	std::copy(_secret_key.begin(), _secret_key.end(), secret_key.begin());
}

Ed25519Key::~Ed25519Key() noexcept
{
	sodium_memzero(&secret_key, sizeof(secret_key));
}

std::string_view
Ed25519Key::GetAlgorithm() const noexcept
{
	return "ssh-ed25519"sv;
}

void
Ed25519Key::SerializePublic(SSH::Serializer &s) const
{
	s.WriteString(GetAlgorithm());

	const auto key_length = s.PrepareLength();
	s.WriteN(public_key);
	s.CommitLength(key_length);
}

void
Ed25519Key::Sign(SSH::Serializer &s, std::span<const std::byte> src) const
{
	s.WriteString(GetAlgorithm());

	s.WriteU32(crypto_sign_ed25519_BYTES);

	auto sig = s.BeginWriteN(crypto_sign_ed25519_BYTES);

	crypto_sign_ed25519_detached(reinterpret_cast<unsigned char *>(sig.data()), nullptr,
				     reinterpret_cast<const unsigned char *>(src.data()), src.size(),
				     reinterpret_cast<const unsigned char *>(secret_key.data()));

	s.CommitWriteN(crypto_sign_ed25519_BYTES);
}
