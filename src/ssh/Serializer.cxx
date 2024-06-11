// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Serializer.hxx"
#include "memory/fb_pool.hxx"
#include "memory/SlicePool.hxx"

#include <random>

namespace SSH {

Serializer::Serializer() noexcept
	:buffer(static_cast<std::byte *>(nullptr), MAX_PACKET_SIZE)
{
	auto alloc = fb_pool_get().Alloc();
	area = alloc.area;
	buffer = std::span<std::byte, MAX_PACKET_SIZE>{static_cast<std::byte *>(alloc.Steal()), MAX_PACKET_SIZE};
}

Serializer::~Serializer() noexcept
{
	if (area != nullptr)
		fb_pool_get().Free(*area, buffer.data());
}

void
Serializer::WriteRandom(std::size_t size)
{
	const auto s = WriteN(size);

	static std::independent_bits_engine<std::default_random_engine, 8, uint8_t> r;
	std::generate(s.begin(), s.end(), [](){
		return static_cast<std::byte>(r());
	});
}

} // namespace SSH
