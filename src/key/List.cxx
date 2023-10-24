// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "List.hxx"
#include "Key.hxx"
#include "util/IterableSplitString.hxx"

KeyList::KeyList() noexcept = default;
KeyList::~KeyList() noexcept = default;

void
KeyList::Add(std::unique_ptr<Key> key) noexcept
{
	auto [it, inserted] = keys.try_emplace(key->GetAlgorithm(), std::move(key));
	if (inserted) {
		if (!algorithms.empty())
			algorithms.push_back(',');
		algorithms.append(it->first);
	}
}

const Key *
KeyList::Choose(std::string_view peer_algorithms) const noexcept
{
	for (const std::string_view a : IterableSplitString(peer_algorithms, ',')) {
		if (a.empty())
			continue;

		const auto i = keys.find(a);
		if (i != keys.end())
			return i->second.get();
	}

	return nullptr;
}
