// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SerializeEVP.hxx"
#include "SerializeEC.hxx"
#include "ssh/Serializer.hxx"
#include "lib/openssl/Error.hxx"
#include "lib/openssl/UniqueEC.hxx"
#include "util/ScopeExit.hxx"

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

void
SerializePublicKey(SSH::Serializer &s, const EVP_PKEY &key)
{
	std::size_t pub_key_size;
	if (!EVP_PKEY_get_octet_string_param(&key, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pub_key_size))
		throw SslError{};

	auto dest = FromBytesStrict<unsigned char>(s.BeginWriteN(pub_key_size));

	if (EVP_PKEY_get_octet_string_param(&key, OSSL_PKEY_PARAM_PUB_KEY, dest.data(), dest.size(),
					    &pub_key_size)) {
		s.CommitWriteN(pub_key_size);
		return;
	}

	const auto group_name = GetStringParam(key, OSSL_PKEY_PARAM_GROUP_NAME);

	const int group_nid = OBJ_sn2nid(group_name.get());
	if (group_nid == NID_undef)
		throw SslError{};

	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(group_nid);
	if (ec_group == nullptr)
		throw SslError{};

	AtScopeExit(ec_group) { EC_GROUP_free(ec_group); };

	const UniqueEC_POINT pub_key{EC_POINT_new(ec_group)};
	if (pub_key == nullptr)
		throw SslError{};

	BIGNUM *priv_key;
	if (!EVP_PKEY_get_bn_param(&key, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key))
		throw SslError{};

	if (!EC_POINT_mul(ec_group, pub_key.get(), priv_key,
			  nullptr, nullptr, nullptr))
		throw SslError{};

	Serialize(s, *pub_key, *ec_group);
}

