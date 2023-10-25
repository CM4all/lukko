// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "lib/openssl/UniqueBN.hxx"
#include "lib/openssl/Error.hxx"

#include <cstddef>
#include <span>

template<bool clear>
inline UniqueBIGNUM<clear>
NewUniqueBIGNUM()
{
	auto *bn = BN_new();
	if (bn == nullptr)
		throw SslError{};

	return UniqueBIGNUM<clear>{bn};
}

template<bool clear>
inline UniqueBIGNUM<clear>
BN_bin2bn(std::span<const std::byte> src)
{
	auto bn = NewUniqueBIGNUM<clear>();
	if (BN_bin2bn(reinterpret_cast<const unsigned char *>(src.data()),
		      src.size(), bn.get()) == nullptr)
		throw SslError{};
	return bn;
}

template<bool clear>
inline UniqueBIGNUM<clear>
BN_sub(const BIGNUM &a, const BIGNUM &b)
{
	auto result = NewUniqueBIGNUM<clear>();
	if (!BN_sub(result.get(), &a, &b))
		throw SslError{};

	return result;
}

template<bool clear>
inline UniqueBIGNUM<clear>
BN_mod_(const BIGNUM &a, const BIGNUM &m, BN_CTX &ctx)
{
	auto result = NewUniqueBIGNUM<clear>();
	if (!BN_mod(result.get(), &a, &m, &ctx))
		throw SslError{};

	return result;
}
