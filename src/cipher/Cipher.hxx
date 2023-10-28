// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace SSH {

/**
 * An abstract interface for stream ciphers used for encrypting
 * outgoing data or for decrypting incoming data on an SSH connection.
 * A separate instance is used for each direction.
 *
 * Some implementations have authentication.  A fixed-size
 * authentication trailer is added at the end of every packet.
 *
 * Some implementations use a different cipher for the packet header
 * (SSH::PacketHeader) and thus need to exclude the header from the
 * usual padding.
 */
class Cipher {
	const std::size_t auth_size;

	const bool pad_without_header;

protected:
	Cipher(std::size_t _auth_size, bool _pad_without_header) noexcept
		:auth_size(_auth_size),
		 pad_without_header(_pad_without_header) {}

public:
	virtual ~Cipher() noexcept = default;

	Cipher(const Cipher &) = delete;
	Cipher &operator=(const Cipher &) = delete;

	/**
	 * Is this an authenticated cipher?
	 */
	bool HasAuth() const noexcept {
		return auth_size > 0;
	}

	/**
	 * How many bytes does the cipher add for authentication after
	 * each packet?
	 */
	std::size_t GetAuthSize() const noexcept {
		return auth_size;
	}

	/**
	 * When generating the padding of a packet, shall the header
	 * size be excluded from the formula?
	 */
	bool IsHeaderExcludedFromPadding() const noexcept {
		return pad_without_header;
	}

	/**
	 * Decrypt the header (SSH::PacketHeader) of an incoming
	 * packet.  The header needs to be decrypted before the rest
	 * can be received, because the recipient needs to know the
	 * packet length.
	 *
	 * Throws on error.
	 *
	 * @param seqnr the sequence number of the packet; this is
	 * used by some implementations as nonce
	 *
	 * @param src the encrypted packet header
	 *
	 * @param dest the destination for the decrypted packet header
	 */
	virtual void DecryptHeader(uint_least64_t seqnr,
				   std::span<const std::byte> src,
				   std::byte *dest) = 0;

	/**
	 * Decrypt the payload.
	 *
	 * Throws on error.
	 *
	 * @param src the whole packet (header, payload, padding and
	 * authentication, if any)
	 *
	 * @param skip_src skip this number of bytes at the beginning
	 * of the packet (the packet header which has already been
	 * decrypted)
	 *
	 * @param dest a buffer large enough to hold the decrypted
	 * payload (including padding)
	 */
	virtual std::size_t Decrypt(uint_least64_t seqnr,
				    std::span<const std::byte> src,
				    std::size_t skip_src,
				    std::span<std::byte> dest) = 0;

	/**
	 * Encrypt a packet (header, payload and padding) and add
	 * authentication.
	 *
	 * Throws on error.
	 *
	 * @param src the whole packet (header, payload, padding)
	 *
	 * @param header_size the portion of #src that is the header
	 * (which may be encrypted differently from the rest)
	 *
	 * @param dest a buffer large enough to hold the encrypted
	 * packet (header, payload, padding and authentication)
	 */
	virtual std::size_t Encrypt(uint_least64_t seqnr,
				    std::span<const std::byte> src,
				    std::size_t header_size,
				    std::byte *dest) = 0;
};

} // namespace SSH
