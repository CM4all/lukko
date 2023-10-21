// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SignECDSA.hxx"
#include "SerializeBN.hxx"
#include "ssh/Serializer.hxx"
#include "lib/openssl/Error.hxx"
#include "util/ScopeExit.hxx"
#include "Digest.hxx"

#include <openssl/obj_mac.h>

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

void
SignECDSA(SSH::Serializer &s,
	  EC_KEY &key, int ecdsa_nid,
	  std::span<const std::byte> src)
{
	const auto hash_alg = sshkey_ec_nid_to_hash_alg(ecdsa_nid);
	const std::size_t hlen = DigestSize(hash_alg);

	std::byte digest[DIGEST_MAX_SIZE];
	Digest(hash_alg, src, digest);
	AtScopeExit(&digest) { sodium_memzero(digest, sizeof(digest)); };

	ECDSA_SIG *esig = ECDSA_do_sign(reinterpret_cast<const unsigned char *>(digest), hlen, &key);
	if (esig == nullptr)
		throw SslError{};

	AtScopeExit(esig) { ECDSA_SIG_free(esig); };

	const BIGNUM *sig_r, *sig_s;
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

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
