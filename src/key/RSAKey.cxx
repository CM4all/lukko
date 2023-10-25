// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "RSAKey.hxx"
#include "ssh/Serializer.hxx"
#include "openssl/EVP.hxx"
#include "openssl/SerializeBN.hxx"
#include "openssl/Sign.hxx"
#include "lib/openssl/Key.hxx"
#include "util/ScopeExit.hxx"

#include <openssl/core_names.h> // for OSSL_PKEY_PARAM_RSA_*

using std::string_view_literals::operator""sv;

RSAKey::RSAKey(Generate)
	:key(GenerateRsaKey())
{
}

std::string_view
RSAKey::GetAlgorithm() const noexcept
{
	return "rsa-sha2-256"sv;
}

void
RSAKey::SerializeKex(SSH::Serializer &s) const
{
	s.WriteString(GetAlgorithm());

	const auto e_length = s.PrepareLength();
	Serialize(s, *GetBNParam<false>(*key, OSSL_PKEY_PARAM_RSA_E));
	s.CommitLength(e_length);

	const auto n_length = s.PrepareLength();
	Serialize(s, *GetBNParam<false>(*key, OSSL_PKEY_PARAM_RSA_N));
	s.CommitLength(n_length);
}

void
RSAKey::Sign(SSH::Serializer &s, std::span<const std::byte> src) const
{
	SignGeneric(s, *key, DigestAlgorithm::SHA256, GetAlgorithm(), src);
}
