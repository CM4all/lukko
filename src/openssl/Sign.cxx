// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Sign.hxx"
#include "Digest.hxx"
#include "SerializeBN.hxx"
#include "ssh/Serializer.hxx"
#include "lib/openssl/Error.hxx"
#include "lib/openssl/UniqueEC.hxx"
#include "lib/openssl/UniqueEVP.hxx"
#include "util/ScopeExit.hxx"
#include "Digest.hxx"

#include <sodium/utils.h>

using std::string_view_literals::operator""sv;

static void
SignDigestOpenSSL(SSH::Serializer &s,
		  EVP_PKEY_CTX &ctx, std::span<const std::byte> digest)
{
	size_t length;
	if (EVP_PKEY_sign(&ctx, nullptr, &length,
			  reinterpret_cast<const unsigned char *>(digest.data()),
			  digest.size()) <= 0)
		throw SslError{"EVP_PKEY_sign() failed"};

	auto dest = s.BeginWriteN(length);
	if (EVP_PKEY_sign(&ctx,
			  reinterpret_cast<unsigned char *>(dest.data()), &length,
			  reinterpret_cast<const unsigned char *>(digest.data()),
			  digest.size()) <= 0)
		throw SslError{"EVP_PKEY_sign() failed"};

	s.CommitWriteN(length);
}

static void
SignDigestOpenSSL(SSH::Serializer &s,
		  EVP_PKEY &key, const EVP_MD &md,
		  std::span<const std::byte> digest)
{
	const UniqueEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(&key, nullptr));
	if (!ctx)
		throw SslError("EVP_PKEY_CTX_new() failed");

	if (EVP_PKEY_sign_init(ctx.get()) <= 0)
		throw SslError("EVP_PKEY_sign_init() failed");

	if (EVP_PKEY_CTX_set_signature_md(ctx.get(), &md) <= 0)
		throw SslError("EVP_PKEY_CTX_set_signature_md() failed");

	SignDigestOpenSSL(s, *ctx, digest);
}

static void
SignOpenSSL(SSH::Serializer &s,
	    EVP_PKEY &key, DigestAlgorithm hash_alg,
	    std::span<const std::byte> src)
{
	const auto *const md = ToEvpMD(hash_alg);
	if (md == nullptr)
		throw std::invalid_argument{"Digest algorithm not supported by OpenSSL"};

	std::byte digest_buffer[DIGEST_MAX_SIZE];
	Digest(hash_alg, src, digest_buffer);
	AtScopeExit(&digest_buffer) { sodium_memzero(digest_buffer, sizeof(digest_buffer)); };

	const std::span digest{digest_buffer, DigestSize(hash_alg)};
	SignDigestOpenSSL(s, key, *md, digest);
}

void
SignGeneric(SSH::Serializer &s,
	    EVP_PKEY &key, DigestAlgorithm hash_alg,
	    std::string_view signature_type,
	    std::span<const std::byte> src)
{
	s.WriteString(signature_type);

	const auto signature_length = s.PrepareLength();
	SignOpenSSL(s, key, hash_alg, src);
	s.CommitLength(signature_length);
}

void
SignECDSA(SSH::Serializer &s,
	  EVP_PKEY &key, DigestAlgorithm hash_alg,
	  std::span<const std::byte> src)
{
	/* write the raw signature to the serializer, convert to
	   ECDSA_SIG (and rewind so we can serialize it again, but
	   this time in SSH format) */
	const auto signature_mark = s.Mark();
	SignOpenSSL(s, key, hash_alg, src);
	const auto signature = s.Since(signature_mark);
	s.Rewind(signature_mark);

	auto signature_data = reinterpret_cast<const unsigned char *>(signature.data());
	const UniqueECDSA_SIG esig{d2i_ECDSA_SIG(nullptr, &signature_data, signature.size())};
        if (esig == nullptr)
		throw SslError{};

	const BIGNUM *sig_r, *sig_s;
	ECDSA_SIG_get0(esig.get(), &sig_r, &sig_s);

	/* now serialize in SSH format */

	constexpr auto signature_type = "ecdsa-sha2-nistp256"sv; // TODO
	s.WriteString(signature_type);

	const auto bn_length = s.PrepareLength();
	const auto r_length = s.PrepareLength();
	Serialize(s, *sig_r);
	s.CommitLength(r_length);
	const auto s_length = s.PrepareLength();
	Serialize(s, *sig_s);
	s.CommitLength(s_length);
	s.CommitLength(bn_length);
}
