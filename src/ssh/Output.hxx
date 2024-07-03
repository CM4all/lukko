// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Queue.hxx"
#include "thread/Job.hxx"

#include <cstddef>
#include <exception>
#include <memory>
#include <mutex>
#include <span>

class BufferedSocket;
class ThreadQueue;

namespace SSH {

class Cipher;

/**
 * Manage output to be sent on a SSH socket.
 */
class Output final : ThreadJob {
	ThreadQueue &thread_queue;
	BufferedSocket &socket;

	uint_least64_t seq = 0;

	std::unique_ptr<Cipher> cipher;

	/**
	 * The cipher to be used once #plain_queue runs empty; it will then 
	 */
	std::unique_ptr<Cipher> next_cipher;

	/**
	 * The cipher used to push new packets.  It is only used by
	 * GetCipher(), which its caller uses to calculate the padding
	 * based on the cipher's characteristics.
	 */
	const Cipher *push_cipher = nullptr;

	/**
	 * Data to be sent as-is on the socket.
	 */
	SendQueue pending_queue;

	/**
	 * Protects #plain_queue, #next_plain_queue, #encrypted_queue,
	 * #next_cipher, #error.
	 */
	std::mutex mutex;

	/**
	 * Data to be encrypted by Run().
	 */
	BufferList plain_queue;

	/**
	 * Data to be encrypted by Run() using #next_cipher.  We need
	 * two queues because #plain_queue needs to be encrypted with
	 * the old cipher.
	 */
	BufferList next_plain_queue;

	/**
	 * Data encrypted by Run().  Will be moved to #pending_queue
	 * by Done().
	 */
	BufferList encrypted_queue;

	/**
	 * An error caught inside of Run() which will be rethrown to
         * the main thread by Flush().
	 */
	std::exception_ptr error;

	/**
	 * Destroy() sets this if the #ThreadJob could not be
	 * canceled; Done() will then delete this object.
	 */
	bool postponed_destroy = false;

	bool auto_reset_seq = false;

public:
	Output(ThreadQueue &_thread_queue, BufferedSocket &_socket) noexcept;

	void Destroy() noexcept;

	bool IsEncrypted() const noexcept {
		return push_cipher != nullptr;
	}

	const Cipher *GetCipher() const noexcept {
		return push_cipher;
	}

	template<typename T>
	void SetCipher(T &&_cipher) noexcept {
		const std::scoped_lock lock{mutex};
		next_cipher = std::forward<T>(_cipher);
		push_cipher = next_cipher.get();
	}

	void AutoResetSeq() noexcept {
		auto_reset_seq = true;
	}

	void Push(std::span<const std::byte> src) noexcept;

	enum class FlushResult {
		DONE,
		MORE,
		DESTROYED,
	};

	FlushResult Flush();

private:
	~Output() noexcept;

	[[nodiscard]]
	AllocatedArray<std::byte> EncryptPacket(std::span<const std::byte> src);

	/* virtual methods from class ThreadJob */
	void Run() noexcept override;
	void Done() noexcept override;
};

} // namespace SSH
