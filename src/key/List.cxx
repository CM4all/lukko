// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "List.hxx"
#include "Key.hxx"
#include "util/IterableSplitString.hxx"

#include <cassert>

SecretKeyList::SecretKeyList() noexcept = default;
SecretKeyList::~SecretKeyList() noexcept = default;

void
SecretKeyList::Add(std::unique_ptr<SecretKey> _key) noexcept
{
	assert(_key);

	keys.emplace_front(std::move(_key));
	const auto &key = *keys.front();

	for (const std::string_view a : IterableSplitString(key.GetAlgorithms(), ',')) {
		auto [it, inserted] = algorithm_to_key.try_emplace(a, &key);
		if (inserted) {
			if (!algorithms.empty())
				algorithms.push_back(',');
			algorithms.append(a);
		}
	}
}

std::pair<const SecretKey *, std::string_view>
SecretKeyList::Choose(std::string_view peer_algorithms) const noexcept
{
	for (const std::string_view a : IterableSplitString(peer_algorithms, ',')) {
		if (a.empty())
			continue;

		if (const auto i = algorithm_to_key.find(a);
		    i != algorithm_to_key.end())
			return {i->second, a};
	}

	return {nullptr, {}};
}
