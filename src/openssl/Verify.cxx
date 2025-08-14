// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "Verify.hxx"
#include "Digest.hxx"
#include "DeserializeBN.hxx"
#include "ssh/Deserializer.hxx"
#include "lib/openssl/Error.hxx"
#include "lib/openssl/UniqueEC.hxx"
#include "lib/openssl/UniqueEVP.hxx"
#include "util/ScopeExit.hxx"

static bool
VerifyDigest(EVP_PKEY &key, const EVP_MD &md,
	     std::span<const std::byte> digest,
	     std::span<const std::byte> signature)
{
	const UniqueEVP_PKEY_CTX ctx{EVP_PKEY_CTX_new(&key, nullptr)};
	if (!ctx)
		throw SslError("EVP_PKEY_CTX_new() failed");

	if (EVP_PKEY_verify_init(ctx.get()) <= 0)
		throw SslError("EVP_PKEY_verify_init() failed");

	if (EVP_PKEY_CTX_set_signature_md(ctx.get(), &md) <= 0)
		throw SslError("EVP_PKEY_CTX_set_signature_md() failed");

	int result = EVP_PKEY_verify(ctx.get(),
				     reinterpret_cast<const unsigned char *>(signature.data()),
				     signature.size(),
				     reinterpret_cast<const unsigned char *>(digest.data()),
				     digest.size());
	if (result == 1)
		return true;
	else if (result == 0)
		return false;
	else
		throw SslError{"EVP_PKEY_verify() failed"};
}

bool
VerifyGeneric(EVP_PKEY &key, DigestAlgorithm hash_alg,
	      std::span<const std::byte> message,
	      std::span<const std::byte> signature)
{
	const auto *const md = ToEvpMD(hash_alg);
	if (md == nullptr)
		throw std::invalid_argument{"Digest algorithm not supported by OpenSSL"};

	std::byte digest_buffer[DIGEST_MAX_SIZE];
	Digest(hash_alg, message, digest_buffer);

	const std::span digest{digest_buffer, DigestSize(hash_alg)};
	return VerifyDigest(key, *md, digest, signature);
}

/**
 * Parse an ECDSA signature in SSH format and convert it to an OpenSSL
 * ECDSA_SIG object.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2
 */
static UniqueECDSA_SIG
DeserializeECDSA_SIG(std::span<const std::byte> src)
{
	SSH::Deserializer d{src};
	auto r = DeserializeBIGNUM(d.ReadLengthEncoded());
	auto s = DeserializeBIGNUM(d.ReadLengthEncoded());

	UniqueECDSA_SIG sig{ECDSA_SIG_new()};
	if (!sig)
		throw SslError{};

	if (!ECDSA_SIG_set0(sig.get(), r.get(), s.get()))
		throw SslError{};

	r.release();
	s.release();

	return sig;
}

bool
VerifyECDSA(EVP_PKEY &key, DigestAlgorithm hash_alg,
	    std::span<const std::byte> message,
	    std::span<const std::byte> signature)
{
	UniqueECDSA_SIG sig = DeserializeECDSA_SIG(signature);

	unsigned char *data = nullptr;
	int result = i2d_ECDSA_SIG(sig.get(), &data);
	if (result < 0)
		throw SslError{"i2d_ECDSA_SIG() failed"};

	AtScopeExit(data) { OPENSSL_free(data); };

	return VerifyGeneric(key, hash_alg,
			     message,
			     {reinterpret_cast<const std::byte *>(data), static_cast<std::size_t>(result)});
}
