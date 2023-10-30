// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "HmacSHA256Cipher.hxx"
#include "util/ByteOrder.hxx"
#include "util/SpanCast.hxx"

#include <sodium/utils.h>

#include <algorithm> // for std::copy_n()
#include <cassert>
#include <stdexcept>

namespace SSH {

HmacSHA256Cipher::HmacSHA256Cipher(std::unique_ptr<Cipher> _next,
				   std::span<const std::byte> _key)
	:Cipher(_next->GetBlockSize(),
		_next->GetAuthSize() + crypto_auth_hmacsha256_BYTES,
		_next->IsHeaderExcludedFromPadding()),
	 next(std::move(_next))
{
	static_assert(sizeof(key) == crypto_auth_hmacsha256_KEYBYTES);

	if (_key.size() < key.size())
		throw std::invalid_argument{"Wrong key size"};

	std::copy_n(_key.begin(), key.size(), key.begin());
}

HmacSHA256Cipher::~HmacSHA256Cipher() noexcept
{
	sodium_memzero(&key, sizeof(key));
}

inline void
HmacSHA256Cipher::InitState(uint_least64_t seqnr) noexcept
{
	crypto_auth_hmacsha256_init(&state,
				    reinterpret_cast<const unsigned char *>(key.data()),
				    key.size());

	const uint32_t seqbuf = ToBE32(seqnr);
	crypto_auth_hmacsha256_update(&state,
				      reinterpret_cast<const unsigned char *>(&seqbuf),
				      sizeof(seqbuf));
}

void
HmacSHA256Cipher::DecryptHeader(uint_least64_t seqnr,
				std::span<const std::byte, HEADER_SIZE> src,
				std::span<std::byte, HEADER_SIZE> dest)
{
	next->DecryptHeader(seqnr, src, dest);

	InitState(seqnr);

	crypto_auth_hmacsha256_update(&state,
				      reinterpret_cast<const unsigned char *>(dest.data()),
				      dest.size());
}

std::size_t
HmacSHA256Cipher::DecryptPayload(uint_least64_t seqnr,
				 std::span<const std::byte> src,
				 std::span<std::byte> dest)
{
	assert(src.size() >= HEADER_SIZE + crypto_auth_hmacsha256_BYTES);

	const auto hmac_received = src.last<crypto_auth_hmacsha256_BYTES>();
	src = src.first(src.size() - crypto_auth_hmacsha256_BYTES);

	const std::size_t result = next->DecryptPayload(seqnr, src, dest);

	/* the state has already been initialized by DecryptHeader();
	   now add the decrypted payload */
	crypto_auth_hmacsha256_update(&state,
				      reinterpret_cast<const unsigned char *>(dest.data()),
				      result);

	std::array<std::byte, crypto_auth_hmacsha256_BYTES> hmac_expected;
	crypto_auth_hmacsha256_final(&state,
				     reinterpret_cast<unsigned char *>(hmac_expected.data()));

	if (!std::equal(hmac_received.begin(), hmac_received.end(),
			hmac_expected.begin()))
		throw std::invalid_argument{"Invalid HMAC"};

	return result;
}

std::size_t
HmacSHA256Cipher::Encrypt(uint_least64_t seqnr,
			  std::span<const std::byte> src,
			  std::byte *dest)
{
	assert(src.size() >= HEADER_SIZE);

	InitState(seqnr);

	crypto_auth_hmacsha256_update(&state,
				      reinterpret_cast<const unsigned char *>(src.data()),
				      src.size());

	std::size_t dest_position = next->Encrypt(seqnr, src, dest);

	crypto_auth_hmacsha256_final(&state,
				     reinterpret_cast<unsigned char *>(dest + dest_position));
	dest_position += crypto_auth_hmacsha256_BYTES;

	return dest_position;
}

} // namespace SSH
