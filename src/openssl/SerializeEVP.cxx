// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "EVP.hxx"
#include "SerializeEVP.hxx"
#include "SerializeEC.hxx"
#include "BN.hxx"
#include "EC.hxx"
#include "ssh/Serializer.hxx"
#include "lib/openssl/Error.hxx"
#include "lib/openssl/UniqueEC.hxx"

#include <openssl/core_names.h>

#include <memory>

static void
SerializeOctetStringParam(SSH::Serializer &s,
			  const EVP_PKEY &key, const char *name)
{
	std::size_t size;
	if (!EVP_PKEY_get_octet_string_param(&key, name, nullptr, 0, &size))
		throw SslError{};

	auto dest = s.BeginWriteN(size);

	if (!EVP_PKEY_get_octet_string_param(&key, name,
					     reinterpret_cast<unsigned char *>(dest.data()),
					     dest.size(), &size))
		throw SslError();

	s.CommitWriteN(size);
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
		break;

	default:
		SerializeOctetStringParam(s, key, OSSL_PKEY_PARAM_PUB_KEY);
	}
}
