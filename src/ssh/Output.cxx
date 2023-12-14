// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Output.hxx"
#include "cipher/Cipher.hxx"
#include "event/net/BufferedSocket.hxx"
#include "net/SocketError.hxx"

#include <cassert>

namespace SSH {

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
	queue.Push(IsEncrypted()
		   ? EncryptPacket(src)
		   : AllocatedArray{src});

	++seq;
}

Output::FlushResult
Output::Flush(BufferedSocket &socket)
{
	std::array<struct iovec, 32> v;
	std::size_t n = queue.Prepare(v);
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

	queue.Consume(nbytes);

	return queue.empty()
		? FlushResult::DONE
		: FlushResult::MORE;
}

} // namespace SSH
