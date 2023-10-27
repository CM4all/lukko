// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace SSH {

class Cipher {
public:
	Cipher() noexcept = default;
	virtual ~Cipher() noexcept = default;

	Cipher(const Cipher &) = delete;
	Cipher &operator=(const Cipher &) = delete;

	[[gnu::pure]]
	virtual std::size_t GetAuthSize() const noexcept = 0;

	virtual void DecryptHeader(uint_least64_t seqnr,
				   std::span<const std::byte> src,
				   std::byte *dest) = 0;

	virtual std::size_t Decrypt(uint_least64_t seqnr,
				    std::span<const std::byte> src,
				    std::size_t skip_src,
				    std::span<std::byte> dest) = 0;

	virtual std::size_t Encrypt(uint_least64_t seqnr,
				    std::span<const std::byte> src,
				    std::size_t header_size,
				    std::byte *dest) noexcept = 0;
};

} // namespace SSH
