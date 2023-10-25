// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "lib/openssl/UniqueBN.hxx"
#include "lib/openssl/Error.hxx"

#include <openssl/evp.h>

inline std::unique_ptr<char[]>
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
inline UniqueBIGNUM<clear>
GetBNParam(const EVP_PKEY &key, const char *name)
{
	BIGNUM *result = nullptr;
	if (!EVP_PKEY_get_bn_param(&key, name, &result))
		throw SslError{};

	return UniqueBIGNUM<clear>{result};
}
