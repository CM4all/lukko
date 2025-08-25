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
	bool hostbased = false;
	bool password = false;

	constexpr std::string_view ToString() const noexcept {
		using std::string_view_literals::operator""sv;

		if (hostbased) {
			if (password) {
				return "publickey,hostbased,password"sv;
			} else {
				return "publickey,hostbased"sv;
			}
		} else {
			if (password) {
				return "publickey,password"sv;
			} else {
				return "publickey"sv;
			}
		}
	}
};

} // namespace SSH
