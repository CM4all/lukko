// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Cipher.hxx"

#include <sodium/crypto_auth_hmacsha256.h>

#include <array>
#include <memory>

namespace SSH {

/**
 * A #Cipher implementation which adds HMAC-SHA2-256 authentication on
 * top of another #Cipher.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6668
 */
class HmacSHA256Cipher final : public Cipher {
	const std::unique_ptr<Cipher> next;

	std::array<std::byte, crypto_auth_hmacsha256_KEYBYTES> key;

	crypto_auth_hmacsha256_state state;

public:
	HmacSHA256Cipher(std::unique_ptr<Cipher> next,
			 std::span<const std::byte> _key);
	~HmacSHA256Cipher() noexcept override;

	void DecryptHeader(uint_least64_t seqnr,
			   std::span<const std::byte, HEADER_SIZE> src,
			   std::span<std::byte, HEADER_SIZE> dest) override;

	std::size_t DecryptPayload(uint_least64_t seqnr,
				   std::span<const std::byte> src,
				   std::span<std::byte> dest) override;

	std::size_t Encrypt(uint_least64_t seqnr,
			    std::span<const std::byte> src,
			    std::byte *dest) override;
};

} // namespace SSH
