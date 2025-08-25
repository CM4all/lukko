// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <string_view>

namespace SSH {

/**
 * A generator for "auth_methods" strings.  Since there are only very
 * few combinations, it's cheaper to have a list of all combinations
 * (instead of generating the string dynamically).
 */
struct AuthMethods {
	static constexpr bool publickey = true;
	static constexpr bool hostbased = true;
	bool password = false;

	constexpr std::string_view ToString() const noexcept {
		using std::string_view_literals::operator""sv;

		if (password) {
			return "publickey,hostbased,password"sv;
		} else {
			return "publickey,hostbased"sv;
		}
	}
};

} // namespace SSH
