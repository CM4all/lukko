// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "config.h"

#include <cstddef>
#include <span>

enum class DigestAlgorithm {
#ifdef HAVE_LIBMD
	SHA1,
#endif
	SHA256,
#ifdef HAVE_LIBMD
	SHA384,
#endif
	SHA512,
};

static constexpr std::size_t DIGEST_MAX_SIZE = 64;

[[gnu::const]]
std::size_t
DigestSize(DigestAlgorithm a) noexcept;

std::size_t
Digest(DigestAlgorithm a, std::span<const std::byte> src,
       std::byte *dest) noexcept;

std::size_t
Digest(DigestAlgorithm a,
       std::initializer_list<std::span<const std::byte>> src,
       std::byte *dest) noexcept;
