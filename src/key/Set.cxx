// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Set.hxx"
#include "Key.hxx"
#include "ssh/Serializer.hxx"
#include "util/SpanCast.hxx"

void
PublicKeySet::Add(std::span<const std::byte> blob,
		  AuthorizedKeyOptions &&options) noexcept
{
	keys.emplace(ToStringView(blob), std::move(options));
}

void
PublicKeySet::Add(const PublicKey &key) noexcept
try {
	SSH::Serializer s;
	key.SerializePublic(s);
	keys.emplace(ToStringView(s.Finish()), AuthorizedKeyOptions{});
} catch (...) {
	// silently ignore serialization errors
}

const AuthorizedKeyOptions *
PublicKeySet::Find(std::span<const std::byte> blob) const noexcept
{
	if (auto i = keys.find(ToStringView(blob)); i != keys.end())
		return &i->second;

	return nullptr;
}

const AuthorizedKeyOptions *
PublicKeySet::Find(const PublicKey &key) const noexcept
try {
	SSH::Serializer s;
	key.SerializePublic(s);
	return Find(s.Finish());
} catch (...) {
	// silently ignore serialization errors
	return nullptr;
}
