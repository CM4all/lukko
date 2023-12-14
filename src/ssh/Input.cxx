// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Input.hxx"
#include "Protocol.hxx"
#include "cipher/Cipher.hxx"
#include "net/SocketProtocolError.hxx"
#include "util/SpanCast.hxx"
#include "DefaultFifoBuffer.hxx"

class DefaultFifoBuffer;

namespace SSH {

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
		cipher->DecryptPayload(seq, r, result);
	assert(nbytes == packet_length);
	src.Consume(need_src);

	return result;
}

std::span<const std::byte>
Input::ReadPacket(DefaultFifoBuffer &src)
{
	if (packet_length == 0) {
		/* read a new PacketHeader */

		auto r = src.Read();
		if (r.size() < sizeof(PacketHeader))
			// need more data
			return {};

		if (cipher) {
			PacketHeader header;
			cipher->DecryptHeader(seq,
					      r.first<sizeof(header)>(),
					      ReferenceAsWritableBytes(header));
			packet_length = header.length;
		} else {
			const auto &header = *reinterpret_cast<const PacketHeader *>(r.data());
			packet_length = header.length;
			src.Consume(sizeof(header));
		}

		if (packet_length == 0)
			/* packets cannot be empty, there must
			   be at least the "padding_length"
			   byte (plus mandatory padding) */
			throw SocketProtocolError{"Empty packet"};

		if (packet_length > MAX_PACKET_SIZE)
			throw SocketProtocolError{"Packet too large"};
	}

	std::span<const std::byte> r;

	if (cipher) {
		decrypted = DecryptPacket(src);
		if (decrypted == nullptr)
			// need more data
			return {};

		r = decrypted;
		assert(r.size() == packet_length);
	} else
		r = src.Read();

	if (r.size() < packet_length)
		// need more data
		return {};

	const std::size_t padding_length = static_cast<uint8_t>(r.front());
	if (padding_length > packet_length - 1)
		throw SocketProtocolError{"Bad padding length"};

	if (!cipher)
		src.Consume(packet_length);

	const auto payload = r.subspan(1, packet_length - padding_length - 1);
	packet_length = 0;

	return payload;
}

} // namespace SSH
