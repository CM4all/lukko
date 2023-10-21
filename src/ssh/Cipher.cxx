// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Cipher.hxx"
#include "lib/sodium/OnetimeauthPoly1305.hxx"
#include "lib/sodium/StreamChaCha20.hxx"
#include "util/ByteOrder.hxx"
#include "util/SpanCast.hxx"

#include <sodium/utils.h>

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

Cipher::Cipher(std::span<const std::byte> key,
	       [[maybe_unused]] std::span<const std::byte> iv)
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

Cipher::~Cipher() noexcept
{
	sodium_memzero(&header_key, sizeof(header_key));
}

void
Cipher::DecryptHeader(uint_least64_t seqnr,
		      std::span<const std::byte> src,
		      std::byte *dest)
{
	const PackedBE64 seqbuf{seqnr};

	crypto_stream_chacha20_xor(dest, src, ReferenceAsBytes(seqbuf), header_key);
}

std::size_t
Cipher::Decrypt(uint_least64_t seqnr,
		std::span<const std::byte> src,
		std::size_t skip_src,
		std::span<std::byte> dest)
{
	assert(src.size() > skip_src + GetAuthSize());

	const PackedBE64 seqbuf{seqnr};

	// check Poly1305 auth of both header and payload
	const auto auth = src.last<crypto_onetimeauth_poly1305_BYTES>();
	src = src.first(src.size() - GetAuthSize());

	const ChaCha20Poly1305Key poly_key{ReferenceAsBytes(seqbuf), payload_key};
	if (!crypto_onetimeauth_poly1305_verify(auth, src, poly_key))
		throw std::invalid_argument{"Invalid Poly1305 MAC"};

	// decrypt the payload
	src = src.subspan(skip_src);
	crypto_stream_chacha20_xor_ic(dest.data(), src, ReferenceAsBytes(seqbuf), 1, payload_key);
	return src.size();
}

std::size_t
Cipher::Encrypt(uint_least64_t seqnr,
		std::span<const std::byte> src,
		std::size_t header_size,
		std::byte *dest) noexcept
{
	assert(src.size() > header_size);

	const PackedBE64 seqbuf{seqnr};

	// encrypt the header
	if (header_size > 0) {
		crypto_stream_chacha20_xor(dest, src, ReferenceAsBytes(seqbuf), header_key);
		src = src.subspan(header_size);
	}

	// encrypt the payload
	crypto_stream_chacha20_xor_ic(dest + header_size, src,
				      ReferenceAsBytes(seqbuf), 1, payload_key);

	// append Poly1305 auth
	const ChaCha20Poly1305Key poly_key{ReferenceAsBytes(seqbuf), payload_key};

	const std::span<std::byte, crypto_onetimeauth_poly1305_BYTES> auth{
		dest + header_size + src.size(),
		crypto_onetimeauth_poly1305_BYTES,
	};

	crypto_onetimeauth_poly1305(auth, {dest, header_size + src.size()}, poly_key);

	return header_size + src.size() + GetAuthSize();
}

} // namespace SSH
