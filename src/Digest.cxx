// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Digest.hxx"

#include <sha2.h>

struct DigestImplementation {
	std::size_t size;
	void (*calculate)(std::initializer_list<std::span<const std::byte>> src,
			  std::byte *dest) noexcept;
};

static void
CalcSHA256(std::initializer_list<std::span<const std::byte>> src, std::byte *dest) noexcept
{
	SHA2_CTX ctx;
	SHA256Init(&ctx);
	for (const auto i : src)
		SHA256Update(&ctx, reinterpret_cast<const uint8_t *>(i.data()), i.size());
	SHA256Final(reinterpret_cast<uint8_t *>(dest), &ctx);
}

static void
CalcSHA384(std::initializer_list<std::span<const std::byte>> src, std::byte *dest) noexcept
{
	SHA2_CTX ctx;
	SHA384Init(&ctx);
	for (const auto i : src)
		SHA384Update(&ctx, reinterpret_cast<const uint8_t *>(i.data()), i.size());
	SHA384Final(reinterpret_cast<uint8_t *>(dest), &ctx);
}

static void
CalcSHA512(std::initializer_list<std::span<const std::byte>> src, std::byte *dest) noexcept
{
	SHA2_CTX ctx;
	SHA512Init(&ctx);
	for (const auto i : src)
		SHA512Update(&ctx, reinterpret_cast<const uint8_t *>(i.data()), i.size());
	SHA512Final(reinterpret_cast<uint8_t *>(dest), &ctx);
}

static constexpr DigestImplementation digest_implementations[] = {
	{
		SHA256_DIGEST_LENGTH,
		CalcSHA256,
	},
	{
		SHA384_DIGEST_LENGTH,
		CalcSHA384,
	},
	{
		SHA512_DIGEST_LENGTH,
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
