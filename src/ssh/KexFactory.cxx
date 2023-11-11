// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "KexFactory.hxx"
#include "util/IterableSplitString.hxx"

using std::string_view_literals::operator""sv;

namespace SSH {

KexAlgorithm
ChooseKexAlgorithm(std::string_view algorithms)
{
	for (const std::string_view a : IterableSplitString(algorithms, ','))
		if (a == "curve25519-sha256"sv)
			return KexAlgorithm::CURVE25519_SHA256;

	throw NoSupportedKexAlgorithm{};
}

} // namespace SSH
