// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SignECDSA.hxx"
#include "SerializeBN.hxx"
#include "ssh/Serializer.hxx"
#include "lib/openssl/Error.hxx"
#include "lib/openssl/UniqueEC.hxx"
#include "lib/openssl/UniqueEVP.hxx"
#include "util/ScopeExit.hxx"
#include "Digest.hxx"

#include <openssl/ec.h>
#include <openssl/rsa.h>

#include <sodium/utils.h>

using std::string_view_literals::operator""sv;

static constexpr u_int
sshkey_curve_nid_to_bits(int nid) noexcept
{
	switch (nid) {
	case NID_X9_62_prime256v1:
		return 256;
	case NID_secp384r1:
		return 384;
	case NID_secp521r1:
		return 521;
	default:
		return 0;
	}
}

static constexpr DigestAlgorithm
sshkey_ec_nid_to_hash_alg(int nid)
{
	int bits = sshkey_curve_nid_to_bits(nid);
	if (bits <= 0)
		throw std::invalid_argument{"Invalid nid"};

	if (bits <= 256)
		return DigestAlgorithm::SHA256;
	else if (bits <= 384)
		return DigestAlgorithm::SHA384;
	else
		return DigestAlgorithm::SHA512;
}

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
		  EVP_PKEY &key,
		  std::span<const std::byte> digest)
{
	const UniqueEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(&key, nullptr));
	if (!ctx)
		throw SslError("EVP_PKEY_CTX_new() failed");

	if (EVP_PKEY_sign_init(ctx.get()) <= 0)
		throw SslError("EVP_PKEY_sign_init() failed");

	if (EVP_PKEY_CTX_set_signature_md(ctx.get(), EVP_sha256()) <= 0)
		throw SslError("EVP_PKEY_CTX_set_signature_md() failed");

	SignDigestOpenSSL(s, *ctx, digest);
}

static void
SignOpenSSL(SSH::Serializer &s,
	    EVP_PKEY &key, int ecdsa_nid,
	    std::span<const std::byte> src)
{
	const auto hash_alg = sshkey_ec_nid_to_hash_alg(ecdsa_nid);

	std::byte digest_buffer[DIGEST_MAX_SIZE];
	Digest(hash_alg, src, digest_buffer);
	AtScopeExit(&digest_buffer) { sodium_memzero(digest_buffer, sizeof(digest_buffer)); };

	const std::span digest{digest_buffer, DigestSize(hash_alg)};
	SignDigestOpenSSL(s, key, digest);
}

void
SignECDSA(SSH::Serializer &s,
	  EVP_PKEY &key, int ecdsa_nid,
	  std::span<const std::byte> src)
{
	/* write the raw signature to the serializer, convert to
	   ECDSA_SIG (and rewind so we can serialize it again, but
	   this time in SSH format) */
	const auto signature_mark = s.Mark();
	SignOpenSSL(s, key, ecdsa_nid, src);
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
