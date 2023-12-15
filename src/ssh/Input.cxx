// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Input.hxx"
#include "IHandler.hxx"
#include "Protocol.hxx"
#include "cipher/Cipher.hxx"
#include "thread/Queue.hxx"
#include "net/SocketProtocolError.hxx"
#include "util/SpanCast.hxx"
#include "DefaultFifoBuffer.hxx"

namespace SSH {

Input::Input(ThreadQueue &_thread_queue, InputHandler &_handler) noexcept
	:thread_queue(_thread_queue), handler(_handler) {}

inline
Input::~Input() noexcept = default;

void
Input::Destroy() noexcept
{
	assert(!postponed_destroy);

	if (thread_queue.Cancel(*this))
		delete this;
	else
		postponed_destroy = true;
}

void
Input::SetCipher(std::unique_ptr<Cipher> _cipher) noexcept
{
	assert(waiting_for_new_cipher);
	assert(packet_length == 0);
	assert(_cipher);

	if (!encrypted) {
		encrypted = true;

		/* initialize decrypt_seq because we'll need it in
		   Run(); we need to add 1 because our caller
		   currently handles a #NEWKEYS packet and hasn't yet
		   called ConsumePacket() */
		decrypt_seq = read_seq + 1;
	}

	{
		const std::scoped_lock lock{mutex};

		waiting_for_new_cipher = false;
		cipher = std::move(_cipher);
	}

	thread_queue.Add(*this);
}

void
Input::ParseHeader(const PacketHeader &header)
{
	packet_length = header.length;

	if (packet_length < 2)
		/* packets cannot be empty, there must be at
		   least the "padding_length" and the
		   "MessageNumber" byte (plus mandatory
		   padding) */
		throw SocketProtocolError{"Empty packet"};

	if (packet_length > MAX_PACKET_SIZE)
		throw SocketProtocolError{"Packet too large"};
}

bool
Input::Feed(DefaultFifoBuffer &src) noexcept
{
	if (encrypted) {
		bool add_job;

		{
			const std::scoped_lock lock{mutex};
			raw_buffer.MoveFromAllowBothNull(src);
			add_job = !raw_buffer.empty() && IsEncrypted() &&
				!waiting_for_new_cipher;
		}

		if (add_job)
			thread_queue.Add(*this);

		return true;
	} else {
		raw_buffer.MoveFromAllowBothNull(src);

		return handler.OnInputReady();
	}
}

inline AllocatedArray<std::byte>
Input::DecryptPacket(DefaultFifoBuffer &src)
{
	assert(cipher);

	const std::size_t need_src = sizeof(PacketHeader) +
		packet_length +
		cipher->GetAuthSize();

	auto r = src.Read();
	if (r.size() < need_src)
		return nullptr;

	r = r.first(need_src);

	AllocatedArray<std::byte> result{packet_length};

	[[maybe_unused]]
	const std::size_t nbytes =
		cipher->DecryptPayload(decrypt_seq, r, result);
	assert(nbytes == packet_length);
	src.Consume(need_src);

	const std::size_t padding_length = static_cast<uint8_t>(result.front());
	if (padding_length > packet_length - 2)
		throw SocketProtocolError{"Bad padding length"};

	/* remove padding */
	result.SetSize(packet_length - padding_length);

	packet_length = 0;
	return result;
}

inline std::span<const std::byte>
Input::ReadUnencryptedPacket()
{
	assert(!waiting_for_new_cipher);

	if (packet_length == 0) {
		/* read a new PacketHeader */

		auto r = raw_buffer.Read();
		if (r.size() < sizeof(PacketHeader))
			// need more data
			return {};

		const auto &header = *reinterpret_cast<const PacketHeader *>(r.data());
		raw_buffer.Consume(sizeof(header));

		ParseHeader(header);
		assert(packet_length > 0);
	}

	const auto r = raw_buffer.Read();
	if (r.size() < packet_length)
		// need more data
		return {};

	const std::size_t padding_length = static_cast<uint8_t>(r.front());
	if (padding_length > packet_length - 2)
		throw SocketProtocolError{"Bad padding length"};

	raw_buffer.Consume(packet_length);

	const auto payload = r.subspan(1, packet_length - padding_length - 1);
	packet_length = 0;

	if (static_cast<MessageNumber>(payload.front()) == MessageNumber::NEWKEYS)
		waiting_for_new_cipher = true;

	return payload;
}

inline std::span<const std::byte>
Input::ReadDecryptedPacket()
{
	assert(!waiting_for_new_cipher);

	if (error)
		std::rethrow_exception(error);

	const std::scoped_lock lock{mutex};

	if (decrypted_list.empty())
		return {};

	// skip the padding_length field
	return std::span{decrypted_list.front()}.subspan(1);
}

std::span<const std::byte>
Input::ReadPacket()
{
	assert(!waiting_for_new_cipher);

	if (IsEncrypted()) {
		consumed_encrypted = true;
		return ReadDecryptedPacket();
	} else {
		return ReadUnencryptedPacket();
	}
}

void
Input::ConsumePacket() noexcept
{
	++read_seq;

	if (consumed_encrypted) {
		const std::scoped_lock lock{mutex};
		assert(!decrypted_list.empty());
		decrypted_list.pop_front();
	}
}

void
Input::Run() noexcept
try {
	{
		const std::scoped_lock lock{mutex};
		if (error || waiting_for_new_cipher)
			return;

		unprotected_buffer.MoveFromAllowBothNull(raw_buffer);
	}

	BufferList unprotected_list;
	bool found_newkeys = false;

	do {
		if (packet_length == 0) {
			/* read a new PacketHeader */

			auto r = unprotected_buffer.Read();
			if (r.size() < sizeof(PacketHeader))
				// need more data
				break;

			PacketHeader header;
			cipher->DecryptHeader(decrypt_seq,
					      r.first<sizeof(header)>(),
					      ReferenceAsWritableBytes(header));
			ParseHeader(header);
		}

		auto decrypted = DecryptPacket(unprotected_buffer);
		if (decrypted == nullptr)
			// need more data
			break;

		assert(decrypted.size() >= 2);

		++decrypt_seq;

		found_newkeys = static_cast<MessageNumber>(decrypted[1]) == MessageNumber::NEWKEYS;

		unprotected_list.emplace_back(std::move(decrypted));
	} while (!found_newkeys);

	{
		const std::scoped_lock lock{mutex};
		decrypted_list.splice(decrypted_list.end(), unprotected_list);

		assert(!waiting_for_new_cipher);
		waiting_for_new_cipher = found_newkeys;

		if (!raw_buffer.empty())
			again = true;

		unprotected_buffer.MoveFromAllowNull(raw_buffer);
	}
} catch (...) {
	const std::scoped_lock lock{mutex};
	error = std::current_exception();
}

void
Input::Done() noexcept
{
	if (postponed_destroy) {
		delete this;
		return;
	}

	bool invoke_ready;

	{
		const std::scoped_lock lock{mutex};
		invoke_ready = error || !decrypted_list.empty();
		raw_buffer.FreeIfEmpty();
	}

	if (invoke_ready)
		handler.OnInputReady();
}

} // namespace SSH
