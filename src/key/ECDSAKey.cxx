// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "ECDSAKey.hxx"
#include "ssh/Serializer.hxx"
#include "openssl/SerializeEVP.hxx"
#include "openssl/SignECDSA.hxx"
#include "lib/openssl/Key.hxx"
#include "util/ScopeExit.hxx"

using std::string_view_literals::operator""sv;

void
ECDSAKey::Generate()
{
	key = GenerateEcKey();
}

std::string_view
ECDSAKey::GetAlgorithm() const noexcept
{
	return "ecdsa-sha2-nistp256"sv;
}

void
ECDSAKey::SerializePublic(SSH::Serializer &s) const
{
	SerializePublicKey(s, *key);
}

void
ECDSAKey::SerializeKex(SSH::Serializer &s) const
{
	constexpr auto ecdsa_curve_id = "nistp256"sv;

	s.WriteString(GetAlgorithm());
	s.WriteString(ecdsa_curve_id);

	const auto key_length = s.PrepareLength();
	SerializePublic(s);
	s.CommitLength(key_length);
}

void
ECDSAKey::Sign(SSH::Serializer &s, std::span<const std::byte> src) const
{
	auto *ec_key = EVP_PKEY_get1_EC_KEY(key.get());
	AtScopeExit(ec_key) { EC_KEY_free(ec_key); };

	constexpr int ec_nid = NID_X9_62_prime256v1; // TODO

	SignECDSA(s, *ec_key, ec_nid, src);

}
