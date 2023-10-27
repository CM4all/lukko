// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "RSAKey.hxx"
#include "ssh/Serializer.hxx"
#include "ssh/Deserializer.hxx"
#include "openssl/EVP.hxx"
#include "openssl/SerializeBN.hxx"
#include "openssl/Sign.hxx"
#include "openssl/Verify.hxx"
#include "lib/openssl/Key.hxx"
#include "util/ScopeExit.hxx"

#include <openssl/core_names.h> // for OSSL_PKEY_PARAM_RSA_*

using std::string_view_literals::operator""sv;

RSAKey::RSAKey(Generate)
	:key(GenerateRsaKey())
{
}

std::string_view
RSAKey::GetType() const noexcept
{
	return "ssh-rsa"sv;
}

std::string_view
RSAKey::GetAlgorithms() const noexcept
{
	return "rsa-sha2-256,rsa-sha2-512,ssh-rsa"sv;
}

void
RSAKey::SerializePublic(SSH::Serializer &s) const
{
	s.WriteString(GetType());

	const auto e_length = s.PrepareLength();
	Serialize(s, *GetBNParam<false>(*key, OSSL_PKEY_PARAM_RSA_E));
	s.CommitLength(e_length);

	const auto n_length = s.PrepareLength();
	Serialize(s, *GetBNParam<false>(*key, OSSL_PKEY_PARAM_RSA_N));
	s.CommitLength(n_length);
}

bool
RSAKey::Verify(std::span<const std::byte> message,
	       std::span<const std::byte> signature) const
{
	SSH::Deserializer d{signature};
	const auto algorithm = d.ReadString();

	DigestAlgorithm hash_alg;
	if (algorithm == "rsa-sha2-256"sv)
		hash_alg = DigestAlgorithm::SHA256;
	else if (algorithm == "rsa-sha2-512"sv)
		hash_alg = DigestAlgorithm::SHA512;
#ifdef HAVE_LIBMD
	else if (algorithm == "ssh-rsa"sv)
		hash_alg = DigestAlgorithm::SHA1;
#endif // HAVE_LIBMD
	else
		throw std::invalid_argument{"Wrong algorithm"};

	signature = d.ReadLengthEncoded();
	return VerifyGeneric(*key, hash_alg, message, signature);
}

void
RSAKey::Sign(SSH::Serializer &s, std::span<const std::byte> src) const
{
	SignGeneric(s, *key, DigestAlgorithm::SHA256, "rsa-sha2-256"sv, src);
}
