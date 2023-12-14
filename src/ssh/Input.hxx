// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "util/AllocatedArray.hxx"

#include <cstddef>
#include <memory>
#include <span>

class DefaultFifoBuffer;
template<typename T> class AllocatedArray;

namespace SSH {

class Cipher;

/**
 * Manage input received on a SSH socket and provides access to
 * individual packets.
 */
class Input final {
	uint_least64_t seq = 0;

	/**
	 * If non-zero, then we're currently waiting for the payload
	 * of a packet to be received.
	 */
	std::size_t packet_length = 0;

	std::unique_ptr<Cipher> cipher;

	/**
	 * Owner of the ReadPacket() return value if the payload was
	 * decrypted.  Will be freed by ConsumePacket().
	 */
	AllocatedArray<std::byte> decrypted;

public:
	bool IsEncrypted() const noexcept {
		return cipher != nullptr;
	}

	template<typename T>
	void SetCipher(T &&_cipher) noexcept {
		cipher = std::forward<T>(_cipher);
	}

	/**
	 * Returns the sequence number of the packet most recently
	 * returned by ReadPacket().
	 */
	uint_least64_t GetSeq() const noexcept {
		return seq;
	}

	/**
	 * Read (and decrypt) the next packet from the buffer.
	 * Returns nullptr if there is not enough data.
	 *
	 * Call ConsumePacket() after processing is finished.
	 *
	 * Throws on error.
	 */
	[[nodiscard]]
	std::span<const std::byte> ReadPacket(DefaultFifoBuffer &src);

	/**
	 *
	 */
	void ConsumePacket() noexcept {
		++seq;
		decrypted = {};
	}

private:
	[[nodiscard]]
	AllocatedArray<std::byte> DecryptPacket(DefaultFifoBuffer &src);
};

} // namespace SSH
