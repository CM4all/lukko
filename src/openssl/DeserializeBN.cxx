// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "DeserializeBN.hxx"
#include "BN.hxx"
#include "lib/openssl/Error.hxx"

#include <stdexcept>

static constexpr std::size_t MAX_BIGNUM = 16384 / 8;

static constexpr bool
IsNegative(std::span<const std::byte> src) noexcept
{
	return !src.empty() && (src.front() & std::byte{0x80}) != std::byte{};
}

static constexpr std::span<const std::byte>
StripLeadingZeroes(std::span<const std::byte> s) noexcept
{
	while (!s.empty() && s.front() == std::byte{})
		s = s.subspan(1);
	return s;
}

UniqueBIGNUM<true>
DeserializeBIGNUM(std::span<const std::byte> src)
{
	if (IsNegative(src))
		throw std::invalid_argument{"Negative BIGNUM"};

	src = StripLeadingZeroes(src);

	if (src.size() > MAX_BIGNUM)
		throw std::invalid_argument{"BIGNUM too large"};

	return BN_bin2bn<true>(src);
}
