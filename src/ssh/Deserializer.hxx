// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Protocol.hxx"
#include "util/SpanCast.hxx"

#include <cstddef>
#include <span>

namespace SSH {

struct MalformedPacket {};

class Deserializer {
	std::span<const std::byte> src;

public:
	explicit constexpr Deserializer(std::span<const std::byte> _src) noexcept
		:src(_src) {}

	std::span<const std::byte> ReadN(std::size_t size) {
		if (src.size() < size)
			throw MalformedPacket{};
		auto result = src.first(size);
		src = src.subspan(size);
		return result;
	}

	uint_least8_t ReadBool() {
		const auto s = ReadN(1);
		return s.front() != std::byte{};
	}

	uint_least8_t ReadU8() {
		const auto s = ReadN(1);
		return static_cast<uint_least8_t>(s.front());
	}

	uint_least32_t ReadU32() {
		const auto s = ReadN(4);
		return (static_cast<uint_least32_t>(s[0]) << 24) |
			(static_cast<uint_least32_t>(s[1]) << 16) |
			(static_cast<uint_least32_t>(s[2]) << 8) |
			static_cast<uint_least32_t>(s[3]);
	}

	std::span<const std::byte> ReadLengthEncoded() {
		return ReadN(ReadU32());
	}

	std::string_view ReadString() {
		return ToStringView(ReadLengthEncoded());
	}

	std::span<const std::byte> GetRest() const noexcept {
		return src;
	}

	void ExpectEnd() const {
		if (!src.empty())
			throw MalformedPacket{};
	}

	using Marker = std::span<const std::byte>::iterator;

	/**
	 * Generate an opaque marker for the current position.
	 */
	constexpr Marker Mark() const noexcept {
		return src.begin();
	}

	/**
	 * Returns a view on the data added since Mark() was called.
	 */
	constexpr std::span<const std::byte> Since(Marker old_position) const noexcept {
		assert(Mark() >= old_position);

		return {old_position, Mark()};
	}
};

} // namespace Mysql
