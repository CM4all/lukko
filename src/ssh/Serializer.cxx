// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Serializer.hxx"
#include "memory/fb_pool.hxx"
#include "memory/SlicePool.hxx"

#include <sodium/randombytes.h>

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

	/* this invokes the getrandom() system call; TODO: switch to a
	   cheaper random source (this is only for padding, not for
	   generating keys) */
	randombytes_buf(s.data(), s.size());
}

} // namespace SSH
