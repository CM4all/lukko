// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

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
	} else if (name == "port-forwarding"sv) {
		if (!value.empty())
			return false;

		no_port_forwarding = false;
		return true;
	} else if (name == "no-port-forwarding"sv) {
		if (!value.empty())
			return false;

		no_port_forwarding = true;
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
		if (!value.empty())
			return false;

		no_port_forwarding = true;
		no_pty = true;
		return true;
	} else if (name == "user-rc"sv || name == "no-user-rc"sv) {
		// not applicable, ignore silently
		return true;
	} else if (name == "agent-forwarding"sv ||
		   name == "no-agent-forwarding"sv ||
		   name == "X11-forwarding"sv ||
		   name == "no-X11-forwarding"sv) {
		// not implemented, ignore silently
		return true;
	} else if (name == "home-read-only"sv) {
		home_read_only = true;
		return true;
	} else
		return false;
}
