// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "StringList.hxx"

namespace SSH {

static constexpr std::string_view
FindCommonAlgorithm(std::string_view preferred, std::string_view supported) noexcept
{
	for (const std::string_view i : IterableSplitString(preferred, ','))
		if (StringListContains(supported, i))
			return i;

	return {};
}

} // namespace SSH
