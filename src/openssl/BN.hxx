// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "lib/openssl/UniqueBN.hxx"
#include "lib/openssl/Error.hxx"

#include <cstddef>
#include <span>

inline UniqueBIGNUM
NewUniqueBIGNUM()
{
	auto *bn = BN_new();
	if (bn == nullptr)
		throw SslError{};

	return UniqueBIGNUM{bn};
}

inline UniqueBIGNUM
BN_bin2bn(std::span<const std::byte> src)
{
	auto bn = NewUniqueBIGNUM();
	if (BN_bin2bn(reinterpret_cast<const unsigned char *>(src.data()),
		      src.size(), bn.get()) == nullptr)
		throw SslError{};
	return bn;
}

inline UniqueBIGNUM
BN_sub(const BIGNUM &a, const BIGNUM &b)
{
	auto result = NewUniqueBIGNUM();
	if (!BN_sub(result.get(), &a, &b))
		throw SslError{};

	return result;
}
