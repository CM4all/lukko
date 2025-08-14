// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "SerializeEVP.hxx"
#include "ssh/Serializer.hxx"
#include "lib/openssl/Error.hxx"

#include <openssl/core_names.h>

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

void
SerializePublicKey(SSH::Serializer &s, const EVP_PKEY &key)
{
	SerializeOctetStringParam(s, key, OSSL_PKEY_PARAM_PUB_KEY);
}
