// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Set.hxx"
#include "Key.hxx"
#include "ssh/Serializer.hxx"
#include "util/SpanCast.hxx"

void
PublicKeySet::Add(std::span<const std::byte> blob) noexcept
{
	keys.emplace(ToStringView(blob));
}

void
PublicKeySet::Add(const PublicKey &key) noexcept
try {
	SSH::Serializer s;
	key.SerializePublic(s);
	keys.emplace(ToStringView(s.Finish()));
} catch (...) {
	// silently ignore serialization errors
}

bool
PublicKeySet::Contains(std::span<const std::byte> blob) const noexcept
{
	return keys.contains(ToStringView(blob));
}

bool
PublicKeySet::Contains(const PublicKey &key) const noexcept
try {
	SSH::Serializer s;
	key.SerializePublic(s);
	return Contains(s.Finish());
} catch (...) {
	// silently ignore serialization errors
	return false;
}
