// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Cipher.hxx"

#include <array>

namespace SSH {

class ChaCha20Poly1305Cipher final : public Cipher {
	std::array<std::byte, 32> payload_key, header_key;

public:
	ChaCha20Poly1305Cipher(std::span<const std::byte> key,
			       std::span<const std::byte> iv);
	~ChaCha20Poly1305Cipher() noexcept override;

	[[gnu::pure]]
	std::size_t GetAuthSize() const noexcept override {
		return 16;
	}

	void DecryptHeader(uint_least64_t seqnr,
			   std::span<const std::byte> src,
			   std::byte *dest) override;

	std::size_t Decrypt(uint_least64_t seqnr,
			    std::span<const std::byte> src,
			    std::size_t skip_src,
			    std::span<std::byte> dest) override;

	std::size_t Encrypt(uint_least64_t seqnr,
			    std::span<const std::byte> src,
			    std::size_t header_size,
			    std::byte *dest) noexcept override;
};

} // namespace SSH
