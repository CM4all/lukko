// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Options.hxx"

using std::string_view_literals::operator""sv;

bool
AuthorizedKeyOptions::Set(std::string_view name, std::string &&value) noexcept
{
	if (name == "command"sv) {
		if (value.empty())
			return false;

		command = std::move(value);
		return true;
	} else if (name == "pty"sv) {
		if (!value.empty())
			return false;

		no_pty = false;
		return true;
	} else if (name == "no-pty"sv) {
		if (!value.empty())
			return false;

		no_pty = true;
		return true;
	} else if (name == "restrict"sv) {
		no_pty = true;
		return true;
	} else if (name == "no-user-rc"sv) {
		// not applicable, ignore silently
		return true;
	} else
		return false;
}
