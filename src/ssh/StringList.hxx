// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "util/IterableSplitString.hxx"

namespace SSH {

static constexpr bool
StringListContains(std::string_view haystack, std::string_view needle) noexcept
{
	for (const std::string_view i : IterableSplitString(haystack, ','))
		if (i == needle)
			return true;

	return false;
}

static constexpr std::string_view
FirstStringListItem(std::string_view list) noexcept
{
	return Split(list, ',').first;
}

} // namespace SSH
