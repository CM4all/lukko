// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Queue.hxx"

#include <cstddef>
#include <memory>
#include <span>

class DefaultFifoBuffer;
class BufferedSocket;

namespace SSH {

class Cipher;

/**
 * Manage output to be sent on a SSH socket.
 */
class Output final {
	uint_least64_t seq = 0;

	std::unique_ptr<Cipher> cipher;

	SendQueue queue;

public:
	bool IsEncrypted() const noexcept {
		return cipher != nullptr;
	}

	const Cipher *GetCipher() const noexcept {
		return cipher.get();
	}

	template<typename T>
	void SetCipher(T &&_cipher) noexcept {
		cipher = std::forward<T>(_cipher);
	}

	void Push(std::span<const std::byte> src);

	enum class FlushResult {
		DONE,
		MORE,
		DESTROYED,
	};

	FlushResult Flush(BufferedSocket &socket);

private:
	[[nodiscard]]
	AllocatedArray<std::byte> EncryptPacket(std::span<const std::byte> src);
};

} // namespace SSH
