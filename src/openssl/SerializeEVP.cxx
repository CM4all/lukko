// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SerializeEVP.hxx"
#include "SerializeEC.hxx"
#include "BN.hxx"
#include "EC.hxx"
#include "ssh/Serializer.hxx"
#include "lib/openssl/Error.hxx"
#include "lib/openssl/UniqueEC.hxx"

#include <openssl/core_names.h>

#include <memory>

static std::unique_ptr<char[]>
GetStringParam(const EVP_PKEY &key, const char *name)
{
	std::size_t length;
	if (!EVP_PKEY_get_utf8_string_param(&key, name, nullptr, 0, &length))
		throw SslError{};

	auto result = std::make_unique<char[]>(length + 1);

	if (!EVP_PKEY_get_utf8_string_param(&key, name, result.get(), length + 1, &length))
		throw SslError{};

	return result;
}

template<bool clear>
static UniqueBIGNUM<clear>
GetBNParam(const EVP_PKEY &key, const char *name)
{
	BIGNUM *result = nullptr;
	if (!EVP_PKEY_get_bn_param(&key, name, &result))
		throw SslError{};

	return UniqueBIGNUM<clear>{result};
}

static UniqueEC_GROUP
GetCurveGroup(const EVP_PKEY &key)
{
	const auto group_name = GetStringParam(key, OSSL_PKEY_PARAM_GROUP_NAME);

	const int group_nid = OBJ_sn2nid(group_name.get());
	if (group_nid == NID_undef)
		throw SslError{};

	UniqueEC_GROUP group{EC_GROUP_new_by_curve_name(group_nid)};
	if (group == nullptr)
		throw SslError{};

	return group;
}

static void
SerializePublicKeyEC(SSH::Serializer &s, const EVP_PKEY &key)
{
	const auto ec_group = GetCurveGroup(key);

	const auto priv_key = GetBNParam<true>(key, OSSL_PKEY_PARAM_PRIV_KEY);
	const auto pub_key = EC_POINT_mul(*ec_group, priv_key.get(),
					  nullptr, nullptr);

	Serialize(s, *pub_key, *ec_group);
}

void
SerializePublicKey(SSH::Serializer &s, const EVP_PKEY &key)
{
	switch (EVP_PKEY_get_base_id(&key)) {
	case EVP_PKEY_EC:
		SerializePublicKeyEC(s, key);
		return;

	default:
		break;
	}

	std::size_t pub_key_size;
	if (!EVP_PKEY_get_octet_string_param(&key, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pub_key_size))
		throw SslError{};

	auto dest = FromBytesStrict<unsigned char>(s.BeginWriteN(pub_key_size));

	if (!EVP_PKEY_get_octet_string_param(&key, OSSL_PKEY_PARAM_PUB_KEY, dest.data(), dest.size(),
					     &pub_key_size))
		throw SslError();

	s.CommitWriteN(pub_key_size);
}
