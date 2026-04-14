// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "util/StringList.hxx"
#include "util/StringSplit.hxx"

namespace SSH {

[[gnu::pure]]
static inline bool
StringListContains(std::string_view haystack, std::string_view needle) noexcept
{
	return ::StringListContains(haystack, ',', needle);
}

static constexpr std::string_view
FirstStringListItem(std::string_view list) noexcept
{
	return Split(list, ',').first;
}

} // namespace SSH
