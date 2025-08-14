// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "Serializer.hxx"
#include "Protocol.hxx"

namespace SSH {

class PacketSerializer : public Serializer {
public:
	PacketSerializer() noexcept = default;

	explicit PacketSerializer(MessageNumber msg) noexcept {
		CommitWriteN(sizeof(PacketHeader) + 1);
		WriteU8(static_cast<uint8_t>(msg));
	}

	std::size_t Pad(std::size_t block_size, std::size_t exclude) {
		const std::size_t padding_length = Padding(size() - exclude, block_size);
		// TODO more padding?
		WriteRandom(padding_length);
		return padding_length;
	}

	std::span<const std::byte> Finish(std::size_t block_size,
					  bool without_header) noexcept {
		auto &header = *reinterpret_cast<PacketHeader *>(buffer.data());

		const std::size_t padding_length = Pad(block_size,
						       without_header ? sizeof(PacketHeader) : 0);
		buffer[sizeof(header)] = static_cast<std::byte>(padding_length);

		const auto result = Serializer::Finish();
		header.length = result.size() - sizeof(header);

		return result;
	}
};

} // namespace Mysql
