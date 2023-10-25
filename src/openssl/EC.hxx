// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "lib/openssl/UniqueEC.hxx"
#include "lib/openssl/Error.hxx"

inline UniqueEC_POINT
EC_POINT_mul(const EC_GROUP &group, const BIGNUM *n,
	     const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx=nullptr)
{
	UniqueEC_POINT result{EC_POINT_new(&group)};
	if (result == nullptr)
		throw SslError{};

	if (!EC_POINT_mul(&group, result.get(), n, q, m, ctx))
		throw SslError{};

	return result;
}
