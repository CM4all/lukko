// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "KexECDH.hxx"
#include "Serializer.hxx"
#include "openssl/DeserializeEC.hxx"
#include "lib/openssl/Error.hxx"
#include "lib/openssl/Key.hxx"
#include "openssl/SerializeEVP.hxx"

using std::string_view_literals::operator""sv;

namespace SSH {

ECDHKex::ECDHKex()
	:key(GenerateEcKey())
{
}

ECDHKex::~ECDHKex() noexcept = default;

static void
EVP_PKEY_derive(Serializer &s, EVP_PKEY_CTX &ctx)
{
	std::size_t size;
	if (EVP_PKEY_derive(&ctx, nullptr, &size) <= 0)
		throw SslError{"EVP_PKEY_derive() failed"};

	auto dest = s.BeginWriteN(size);

	if (EVP_PKEY_derive(&ctx, reinterpret_cast<unsigned char *>(dest.data()),
			    &size) <= 0)
		throw SslError{"EVP_PKEY_derive() failed"};

	s.CommitWriteN(size);

	if ((dest.front() & std::byte{0x80}) != std::byte{})
		/* prepend null byte to avoid interpretation as
		   negative number */
		s.InsertNullByte(dest.size());
}

void
ECDHKex::SerializeEphemeralPublicKey(Serializer &s) const
{
	SerializePublicKey(s, *key);
}

void
ECDHKex::GenerateSharedSecret(std::span<const std::byte> client_ephemeral_public_key,
			      Serializer &shared_secret)
{
	const auto client_key = DeserializeECPublic("P-256"sv, client_ephemeral_public_key);

	const UniqueEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
	if (!ctx)
		throw SslError{"EVP_PKEY_CTX_new() failed"};

	if (EVP_PKEY_derive_init(ctx.get()) <= 0)
		throw SslError{"EVP_PKEY_derive_init() failed"};

	if (EVP_PKEY_derive_set_peer(ctx.get(), client_key.get()) <= 0)
		throw SslError{"EVP_PKEY_derive_set_peer() failed"};

	const auto length = shared_secret.PrepareLength();
	EVP_PKEY_derive(shared_secret, *ctx);
	shared_secret.CommitLength(length);
}

} // namespace SSH
