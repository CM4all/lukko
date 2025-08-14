// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "OsslCipher.hxx"
#include "lib/openssl/Error.hxx"
#include "util/ByteOrder.hxx"
#include "util/SpanCast.hxx"

#include <algorithm> // for std::copy_n()
#include <stdexcept>
#include <utility> // for std::cmp_less()

namespace SSH {

static bool
EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX &ctx, int cmd, std::span<const std::byte> p) noexcept
{
	return EVP_CIPHER_CTX_ctrl(&ctx, cmd, p.size(),
				   const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(p.data())));
}

static int
EVP_CipherUpdate(EVP_CIPHER_CTX &ctx, std::byte *out, int *outl,
		 std::span<const std::byte> in) noexcept
{
	return EVP_CipherUpdate(&ctx,
				reinterpret_cast<unsigned char *>(out), outl,
				reinterpret_cast<const unsigned char *>(in.data()),
				in.size());
}

static int
EVP_CipherFinal_ex(EVP_CIPHER_CTX &ctx, std::byte *out, int *outl) noexcept
{
	return EVP_CipherFinal_ex(&ctx,
				  reinterpret_cast<unsigned char *>(out), outl);
}

OsslCipher::OsslCipher(const EVP_CIPHER &cipher,
		       std::size_t _block_size,
		       std::size_t _auth_size,
		       std::span<const std::byte> key,
		       std::span<const std::byte> iv,
		       bool do_encrypt)
	:Cipher(_block_size, _auth_size, _auth_size > 0),
	 ctx(EVP_CIPHER_CTX_new())
{
	if (ctx == nullptr)
		throw SslError{};

	if (std::cmp_less(iv.size(), EVP_CIPHER_get_iv_length(&cipher)))
	    throw std::invalid_argument{"Bad IV"};

	if (!EVP_CipherInit(ctx.get(), &cipher, nullptr,
			    reinterpret_cast<const unsigned char *>(iv.data()),
			    do_encrypt))
		throw SslError{"EVP_CipherInit() failed"};

	if (HasAuth() &&
	    !EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IV_FIXED, -1, const_cast<std::byte *>(iv.data())))
		throw SslError{"EVP_CTRL_GCM_SET_IV_FIXED failed"};

	if (int key_length = EVP_CIPHER_CTX_get_key_length(ctx.get());
	    key_length > 0 && static_cast<int>(key.size()) != key_length)
		throw std::invalid_argument{"Wrong key size"};

	if (!EVP_CipherInit(ctx.get(), nullptr,
			    reinterpret_cast<const unsigned char *>(key.data()),
			    nullptr, -1))
		throw SslError{"EVP_CipherInit() failed"};
}

OsslCipher::~OsslCipher() noexcept = default;

inline void
OsslCipher::IncrementIV()
{
	std::byte last_iv[1];
	if (!EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_IV_GEN, last_iv))
		throw SslError{"EVP_CTRL_GCM_IV_GEN failed"};
}

void
OsslCipher::DecryptHeader([[maybe_unused]] uint_least64_t seqnr,
			  std::span<const std::byte, HEADER_SIZE> src,
			  std::span<std::byte, HEADER_SIZE> dest)
{
	if (HasAuth()) {
		std::copy(src.begin(), src.end(), dest.begin());
	} else {
		int outl;
		if (EVP_CipherUpdate(*ctx, dest.data(), &outl, src) < 0)
			throw SslError{"EVP_Cipher() failed"};

		assert(outl == (int)dest.size());
	}
}

std::size_t
OsslCipher::DecryptPayload([[maybe_unused]] uint_least64_t seqnr,
			   std::span<const std::byte> src,
			   std::span<std::byte> dest)
{
	assert(src.size() >= HEADER_SIZE + GetAuthSize());

	if (HasAuth()) {
		IncrementIV();

		/* use the GCM tag and strip it from the "src"
		   parameter */
		if (!EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_TAG,
					 src.last(GetAuthSize())))
			throw SslError{"EVP_CTRL_GCM_SET_TAG failed"};

		src = src.first(src.size() - GetAuthSize());
	}

	int outl;
	if (HasAuth() &&
	    EVP_CipherUpdate(*ctx, nullptr, &outl,
			     src.first<HEADER_SIZE>()) != 1)
		throw SslError{"EVP_CipherUpdate() failed"};

	assert(IsHeaderExcludedFromPadding() || (src.size() % GetBlockSize()) == 0);

	src = src.subspan(HEADER_SIZE);

	assert(!IsHeaderExcludedFromPadding() || (src.size() % GetBlockSize()) == 0);

	std::size_t dest_position = 0;
	if (EVP_CipherUpdate(*ctx, dest.data() + dest_position, &outl, src) != 1)
		throw SslError{"EVP_CipherUpdate() failed"};

	dest_position += outl;

	if (EVP_CipherFinal_ex(*ctx, dest.data() + dest_position, &outl) != 1)
		throw SslError{"EVP_CipherUpdate() failed"};

	dest_position += outl;

	return dest_position;
}

std::size_t
OsslCipher::Encrypt([[maybe_unused]] uint_least64_t seqnr,
		    std::span<const std::byte> src,
		    std::byte *dest)
{
	assert(src.size() >= HEADER_SIZE + GetAuthSize());
	assert(IsHeaderExcludedFromPadding() || (src.size() % GetBlockSize()) == 0);

	std::size_t dest_position = 0;

	if (HasAuth())
		IncrementIV();

	int outl;
	if (HasAuth()) {
		if (EVP_CipherUpdate(*ctx, nullptr, &outl,
				     src.first<HEADER_SIZE>()) != 1)
			throw SslError{"EVP_CipherUpdate() failed"};

		std::copy_n(src.begin(), HEADER_SIZE, dest + dest_position);
		dest_position += HEADER_SIZE;
		src = src.subspan(HEADER_SIZE);
	}

	assert(!IsHeaderExcludedFromPadding() || (src.size() % GetBlockSize()) == 0);

	if (EVP_CipherUpdate(*ctx, dest + dest_position, &outl, src) != 1)
		throw SslError{"EVP_CipherUpdate() failed"};

	dest_position += outl;

	if (EVP_CipherFinal_ex(*ctx, dest + dest_position, &outl) != 1)
		throw SslError{"EVP_CipherFinal_ex() failed"};

	dest_position += outl;

	if (HasAuth()) {
		if (!EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_GET_TAG,
					 {dest + dest_position, GetAuthSize()}))
			throw SslError{"EVP_CTRL_GCM_GET_TAG failed"};

		dest_position += GetAuthSize();
	}

	return dest_position;
}

} // namespace SSH
