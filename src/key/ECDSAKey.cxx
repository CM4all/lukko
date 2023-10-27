// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "ECDSAKey.hxx"
#include "ssh/Serializer.hxx"
#include "ssh/Deserializer.hxx"
#include "openssl/SerializeEVP.hxx"
#include "openssl/Sign.hxx"
#include "openssl/Verify.hxx"
#include "lib/openssl/Key.hxx"

using std::string_view_literals::operator""sv;

ECDSAKey::ECDSAKey(Generate)
	:key(GenerateEcKey())
{
}

std::string_view
ECDSAKey::GetType() const noexcept
{
	return "ecdsa-sha2-nistp256"sv;
}

std::string_view
ECDSAKey::GetAlgorithms() const noexcept
{
	return "ecdsa-sha2-nistp256"sv;
}

void
ECDSAKey::SerializePublic(SSH::Serializer &s) const
{
	constexpr auto ecdsa_curve_id = "nistp256"sv;

	s.WriteString(GetType());
	s.WriteString(ecdsa_curve_id);

	const auto key_length = s.PrepareLength();
	SerializePublicKey(s, *key);
	s.CommitLength(key_length);
}

bool
ECDSAKey::Verify(std::span<const std::byte> message,
		 std::span<const std::byte> signature) const
{
	SSH::Deserializer d{signature};
	const auto algorithm = d.ReadString();

	DigestAlgorithm hash_alg;
	if (algorithm == "ecdsa-sha2-nistp256"sv)
		hash_alg = DigestAlgorithm::SHA256;
	else
		throw std::invalid_argument{"Wrong algorithm"};

	signature = d.ReadLengthEncoded();
	return VerifyECDSA(*key, hash_alg, message, signature);
}

void
ECDSAKey::Sign(SSH::Serializer &s, std::span<const std::byte> src) const
{
	constexpr DigestAlgorithm hash_alg = DigestAlgorithm::SHA256; // TODO

	SignECDSA(s, *key, hash_alg, src);
}
