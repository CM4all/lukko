// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "Cipher.hxx"
#include "lib/sodium/ChaCha20Types.hxx"

namespace SSH {

class ChaCha20Poly1305Cipher final : public Cipher {
	ChaCha20Key payload_key, header_key;

public:
	explicit ChaCha20Poly1305Cipher(std::span<const std::byte> key);
	~ChaCha20Poly1305Cipher() noexcept override;

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
