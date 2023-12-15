// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "List.hxx"
#include "thread/Job.hxx"
#include "DefaultFifoBuffer.hxx"

#include <cstddef>
#include <exception>
#include <memory>
#include <mutex>
#include <span>

class ThreadQueue;
template<typename T> class AllocatedArray;

namespace SSH {

struct PacketHeader;
class Cipher;
class InputHandler;

/**
 * Manage input received on a SSH socket and provides access to
 * individual packets.
 */
class Input final : ThreadJob {
	ThreadQueue &thread_queue;
	InputHandler &handler;

	/**
	 * The sequence of the packet returned by ReadPacket().
	 */
	uint_least64_t read_seq = 0;

	/**
	 * The sequence of the next packet to be decrypted.
	 * Initialized by the first SetCipher() call.
	 */
	uint_least64_t decrypt_seq;

	/**
	 * If non-zero, then we're currently waiting for the payload
	 * of a packet to be received.
	 */
	std::size_t packet_length = 0;

	std::unique_ptr<Cipher> cipher;

	/**
	 * Protects #raw_buffer, #decrypted_list,
	 * #waiting_for_new_cipher, #error.
	 */
	std::mutex mutex;

	std::exception_ptr error;

	/**
	 * Raw input from the socket.  It may need to be decrypted.
	 */
	DefaultFifoBuffer raw_buffer;

	/**
	 * A buffer for use within Run().  Unlike #raw_buffer, it is
	 * not protected by a mutex.
	 */
	DefaultFifoBuffer unprotected_buffer;

	/**
	 * Decrypted packet payloads filled by Run().  Only used if
	 * there is a cipher.
	 */
	BufferList decrypted_list;

	bool encrypted = false;

	/**
	 * Destroy() sets this if the #ThreadJob could not be
	 * canceled; Done() will then delete this object.
	 */
	bool postponed_destroy = false;

	/**
	 * True after seeing a #NEWKEYS packet.  It means #raw_buffer
	 * needs to be decrypted, but we don't have the #Cipher
	 * instance for it yet.  Decrypting can be resumed as son as
	 * SetCipher() gets called.
	 */
	bool waiting_for_new_cipher = false;

	/**
	 * Was the last packet returned by ReadPacket() encrypted?
	 */
	bool consumed_encrypted = false;

public:
	Input(ThreadQueue &_thread_queue, InputHandler &_handler) noexcept;

	void Destroy() noexcept;

	bool IsEncrypted() const noexcept {
		return encrypted;
	}

	void SetCipher(std::unique_ptr<Cipher> _cipher) noexcept;

	/**
	 * Returns the sequence number of the packet most recently
	 * returned by ReadPacket().
	 */
	uint_least64_t GetSeq() const noexcept {
		return read_seq;
	}

	/**
	 * Feed data received on the socket into the packetizer.  This
	 * will lead to a InputHandler::OnInputReady() call as soon as
	 * packets have been decrypted.
	 *
	 * @return false if the #Input was destroyed
	 */
	bool Feed(DefaultFifoBuffer &src) noexcept;

	/**
	 * Read (and decrypt) the next packet from the buffer.
	 * Returns nullptr if there is not enough data.
	 *
	 * Call ConsumePacket() after processing is finished.
	 *
	 * Throws on error.
	 */
	[[nodiscard]]
	std::span<const std::byte> ReadPacket();

	/**
	 * Mark the packet returned by ReadPacket() as "consumed".
	 */
	void ConsumePacket() noexcept;

private:
	~Input() noexcept;

	/**
	 * Throws on error.
	 */
	void ParseHeader(const PacketHeader &header);

	[[nodiscard]]
	std::span<const std::byte> ReadUnencryptedPacket();

	[[nodiscard]]
	std::span<const std::byte> ReadDecryptedPacket();

	[[nodiscard]]
	AllocatedArray<std::byte> DecryptPacket(DefaultFifoBuffer &src);

	/* virtual methods from class ThreadJob */
	void Run() noexcept override;
	void Done() noexcept override;
};

} // namespace SSH
