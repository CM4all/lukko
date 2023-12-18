// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Output.hxx"
#include "cipher/Cipher.hxx"
#include "thread/Queue.hxx"
#include "event/net/BufferedSocket.hxx"
#include "net/SocketError.hxx"

#include <cassert>

namespace SSH {

Output::Output(ThreadQueue &_thread_queue, BufferedSocket &_socket) noexcept
	:thread_queue(_thread_queue), socket(_socket) {}

inline
Output::~Output() noexcept = default;

void
Output::Destroy() noexcept
{
	assert(!postponed_destroy);

	if (thread_queue.Cancel(*this))
		delete this;
	else
		postponed_destroy = true;
}

inline AllocatedArray<std::byte>
Output::EncryptPacket(std::span<const std::byte> src)
{
	assert(cipher);

	AllocatedArray<std::byte> dest{src.size() + 256};

	const std::size_t encrypted_size =
		cipher->Encrypt(seq, src, dest.data());
	dest.SetSize(encrypted_size);
	return dest;
}

void
Output::Push(std::span<const std::byte> src)
{
	AllocatedArray<std::byte> copy{src};

	if (IsEncrypted()) {
		{
			const std::scoped_lock lock{mutex};

			/* if there's a next_cipher, push to
			   next_plain_queue instead of plain_queue */
			auto &queue = next_cipher
				? next_plain_queue
				: plain_queue;

			queue.emplace_back(std::move(copy));
		}

		thread_queue.Add(*this);
	} else {
		pending_queue.Push(std::move(copy));
		++seq;

		socket.DeferWrite();
	}
}

Output::FlushResult
Output::Flush()
{
	if (IsEncrypted()) {
		const std::scoped_lock lock{mutex};
		pending_queue.MoveFrom(encrypted_queue);
	}

	std::array<struct iovec, 32> v;
	std::size_t n = pending_queue.Prepare(v);
	if (n == 0)
		return FlushResult::DONE;

	const auto nbytes = socket.WriteV(std::span{v}.first(n));
	if (nbytes < 0) [[unlikely]] {
		switch (static_cast<write_result>(nbytes)) {
		case WRITE_SOURCE_EOF:
			// unreachable
			break;

		case WRITE_ERRNO:
			break;

		case WRITE_BLOCKING:
			return FlushResult::MORE;

		case WRITE_DESTROYED:
			return FlushResult::DESTROYED;

		case WRITE_BROKEN:
			break;
		}

		throw MakeSocketError("send failed");
	}

	pending_queue.Consume(nbytes);

	return pending_queue.empty()
		? FlushResult::DONE
		: FlushResult::MORE;
}

void
Output::Run() noexcept
{
	BufferList src, dest;

	{
		const std::scoped_lock lock{mutex};

		if (plain_queue.empty() && next_cipher) {
			/* switch to next_cipher */
			cipher = std::move(next_cipher);
			plain_queue.swap(next_plain_queue);

			if (auto_reset_seq)
				seq = 0;
		}

		src.swap(plain_queue);
	}

	while (!src.empty()) {
		dest.emplace_back(EncryptPacket(src.front()));
		++seq;
		src.pop_front();
	}

	{
		const std::scoped_lock lock{mutex};
		encrypted_queue.splice(encrypted_queue.end(), dest);

		if (plain_queue.empty() && !next_plain_queue.empty())
			again = true;
	}
}

void
Output::Done() noexcept
{
	if (postponed_destroy) {
		delete this;
		return;
	}

	socket.DeferWrite();
}

} // namespace SSH
