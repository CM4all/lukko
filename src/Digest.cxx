// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Digest.hxx"
#include "lib/sodium/SHA256.hxx"
#include "lib/sodium/SHA512.hxx"

#include <sha2.h>

struct DigestImplementation {
	std::size_t size;
	void (*calculate)(std::initializer_list<std::span<const std::byte>> src,
			  std::byte *dest) noexcept;
};

static void
CalcSHA256(std::initializer_list<std::span<const std::byte>> src, std::byte *dest) noexcept
{
	static_assert(DIGEST_MAX_SIZE >= crypto_hash_sha256_BYTES);

	SHA256State state;
	for (const auto i : src)
		state.Update(i);
	state.Final(std::span<std::byte, crypto_hash_sha256_BYTES>{dest, crypto_hash_sha256_BYTES});
}

#ifdef HAVE_LIBMD

static void
CalcSHA384(std::initializer_list<std::span<const std::byte>> src, std::byte *dest) noexcept
{
	SHA2_CTX ctx;
	SHA384Init(&ctx);
	for (const auto i : src)
		SHA384Update(&ctx, reinterpret_cast<const uint8_t *>(i.data()), i.size());
	SHA384Final(reinterpret_cast<uint8_t *>(dest), &ctx);
}

#endif // HAVE_LIBMD

static void
CalcSHA512(std::initializer_list<std::span<const std::byte>> src, std::byte *dest) noexcept
{
	static_assert(DIGEST_MAX_SIZE >= crypto_hash_sha512_BYTES);

	SHA512State state;
	for (const auto i : src)
		state.Update(i);
	state.Final(std::span<std::byte, crypto_hash_sha512_BYTES>{dest, crypto_hash_sha512_BYTES});
}

static constexpr DigestImplementation digest_implementations[] = {
	{
		crypto_hash_sha256_BYTES,
		CalcSHA256,
	},
#ifdef HAVE_LIBMD
	{
		SHA384_DIGEST_LENGTH,
		CalcSHA384,
	},
#endif // HAVE_LIBMD
	{
		crypto_hash_sha512_BYTES,
		CalcSHA512,
	},
};

static constexpr const DigestImplementation &
GetDigestImplementation(DigestAlgorithm a) noexcept
{
	return digest_implementations[static_cast<std::size_t>(a)];
}

std::size_t
DigestSize(DigestAlgorithm a) noexcept
{
	const auto &i = GetDigestImplementation(a);
	return i.size;
}

std::size_t
Digest(DigestAlgorithm a, std::span<const std::byte> src,
       std::byte *dest) noexcept
{
	const auto &i = GetDigestImplementation(a);
	i.calculate({src}, dest);
	return i.size;
}

std::size_t
Digest(DigestAlgorithm a,
       std::initializer_list<std::span<const std::byte>> src,
       std::byte *dest) noexcept
{
	const auto &i = GetDigestImplementation(a);
	i.calculate(src, dest);
	return i.size;
}
