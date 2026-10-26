// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "PerUser.hxx"
#include "util/djb_hash.hxx"
#include "util/SpanCast.hxx"

constexpr std::size_t
PerUserAccounting::Hash::operator()(std::string_view s) const noexcept
{
	return djb_hash(AsBytes(s));
}

PerUserAccountingLease
UserAccountingMap::operator[](std::string_view name) noexcept
{
	auto [i, inserted] = map.insert_check(name);
	if (inserted) {
		auto *per_user = new PerUserAccounting(name);
		map.insert_commit(i, *per_user);
		return PerUserAccountingLease{*per_user};
	} else
		return PerUserAccountingLease{*i};
}
