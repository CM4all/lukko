// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Cipher.hxx"
#include "lib/openssl/UniqueEVP.hxx"

namespace SSH {

class OsslCipher final : public Cipher {
	UniqueEVP_CIPHER_CTX ctx;

public:
	OsslCipher(const EVP_CIPHER &cipher,
		   std::size_t _block_size,
		   std::size_t _auth_size,
		   std::span<const std::byte> key,
		   std::span<const std::byte> iv,
		   bool do_encrypt);
	~OsslCipher() noexcept override;

	void DecryptHeader(uint_least64_t seqnr,
			   std::span<const std::byte, HEADER_SIZE> src,
			   std::span<std::byte, HEADER_SIZE> dest) override;

	std::size_t DecryptPayload(uint_least64_t seqnr,
				   std::span<const std::byte> src,
				   std::span<std::byte> dest) override;

	std::size_t Encrypt(uint_least64_t seqnr,
			    std::span<const std::byte> src,
			    std::byte *dest) override;

private:
	void IncrementIV();
};

} // namespace SSH
