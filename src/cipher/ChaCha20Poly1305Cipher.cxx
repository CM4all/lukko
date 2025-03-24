// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "ChaCha20Poly1305Cipher.hxx"
#include "lib/sodium/OnetimeauthPoly1305.hxx"
#include "lib/sodium/StreamChaCha20.hxx"
#include "util/PackedBigEndian.hxx"
#include "util/SpanCast.hxx"

#include <sodium/utils.h>

#include <algorithm> // for std::copy()
#include <cassert>
#include <stdexcept>

/**
 * Helper class which generates a Poly1305 key for ChaCha20Poly1305.
 */
class ChaCha20Poly1305Key {
	std::array<std::byte, crypto_onetimeauth_poly1305_KEYBYTES> key{};

public:
	ChaCha20Poly1305Key(std::span<const std::byte, crypto_stream_chacha20_NONCEBYTES> chacha20_nonce,
			    std::span<const std::byte, crypto_stream_chacha20_KEYBYTES> chacha20_key) noexcept {
		crypto_stream_chacha20_xor(key.data(), key, chacha20_nonce, chacha20_key);
	}

	~ChaCha20Poly1305Key() noexcept {
		sodium_memzero(this, sizeof(*this));
	}

	operator std::span<const std::byte, crypto_onetimeauth_poly1305_KEYBYTES>() const noexcept {
		return key;
	}
};

namespace SSH {

ChaCha20Poly1305Cipher::ChaCha20Poly1305Cipher(std::span<const std::byte> key)
	:Cipher(8, 16, true)
{
	static_assert(sizeof(payload_key) == crypto_stream_chacha20_KEYBYTES);
	static_assert(sizeof(header_key) == crypto_stream_chacha20_KEYBYTES);

	if (key.size() != sizeof(payload_key) + sizeof(header_key))
		throw std::invalid_argument{"Wrong key size"};

	const auto _payload_key = key.first<crypto_stream_chacha20_KEYBYTES>();
	const auto _header_key = key.last<crypto_stream_chacha20_KEYBYTES>();

	std::copy(_payload_key.begin(), _payload_key.end(), payload_key.begin());
	std::copy(_header_key.begin(), _header_key.end(), header_key.begin());
}

ChaCha20Poly1305Cipher::~ChaCha20Poly1305Cipher() noexcept
{
	sodium_memzero(&header_key, sizeof(header_key));
}

void
ChaCha20Poly1305Cipher::DecryptHeader(uint_least64_t seqnr,
				      std::span<const std::byte, HEADER_SIZE> src,
				      std::span<std::byte, HEADER_SIZE> dest)
{
	const PackedBE64 seqbuf{seqnr};

	crypto_stream_chacha20_xor(dest.data(), src, ReferenceAsBytes(seqbuf),
				   header_key);
}

std::size_t
ChaCha20Poly1305Cipher::DecryptPayload(uint_least64_t seqnr,
				       std::span<const std::byte> src,
				       std::span<std::byte> dest)
{
	assert(src.size() > HEADER_SIZE + GetAuthSize());

	const PackedBE64 seqbuf{seqnr};

	// check Poly1305 auth of both header and payload
	const auto auth = src.last<crypto_onetimeauth_poly1305_BYTES>();
	src = src.first(src.size() - GetAuthSize());

	const ChaCha20Poly1305Key poly_key{ReferenceAsBytes(seqbuf), payload_key};
	if (!crypto_onetimeauth_poly1305_verify(auth, src, poly_key))
		throw std::invalid_argument{"Invalid Poly1305 MAC"};

	// decrypt the payload
	src = src.subspan(HEADER_SIZE);
	crypto_stream_chacha20_xor_ic(dest.data(), src, ReferenceAsBytes(seqbuf), 1, payload_key);
	return src.size();
}

std::size_t
ChaCha20Poly1305Cipher::Encrypt(uint_least64_t seqnr,
				std::span<const std::byte> src,
				std::byte *dest)
{
	assert(src.size() > HEADER_SIZE);

	const PackedBE64 seqbuf{seqnr};

	// encrypt the header
	crypto_stream_chacha20_xor(dest, src.first<HEADER_SIZE>(),
				   ReferenceAsBytes(seqbuf), header_key);
	src = src.subspan(HEADER_SIZE);

	// encrypt the payload
	crypto_stream_chacha20_xor_ic(dest + HEADER_SIZE, src,
				      ReferenceAsBytes(seqbuf), 1, payload_key);

	// append Poly1305 auth
	const ChaCha20Poly1305Key poly_key{ReferenceAsBytes(seqbuf), payload_key};

	const std::span<std::byte, crypto_onetimeauth_poly1305_BYTES> auth{
		dest + HEADER_SIZE + src.size(),
		crypto_onetimeauth_poly1305_BYTES,
	};

	crypto_onetimeauth_poly1305(auth, {dest, HEADER_SIZE + src.size()}, poly_key);

	return HEADER_SIZE + src.size() + GetAuthSize();
}

} // namespace SSH
