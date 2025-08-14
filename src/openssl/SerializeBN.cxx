// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "SerializeBN.hxx"
#include "ssh/Serializer.hxx"
#include "lib/openssl/Error.hxx"

#include <stdexcept>

static constexpr std::size_t MAX_BIGNUM = 16384 / 8;

void
Serialize(SSH::Serializer &s, const BIGNUM &bn)
{
	const int length = BN_num_bytes(&bn);
	if (length < 0 || std::size_t(length) > MAX_BIGNUM)
		throw std::invalid_argument{"Invalid BN size"};

	auto dest = s.BeginWriteN(length);
	if (BN_bn2bin(&bn, reinterpret_cast<unsigned char *>(dest.data())) != length)
		throw SslError{};

	s.CommitBignum2(length);
}
