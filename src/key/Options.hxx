// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <string>

/**
 * Options specified in an "authorized_keys" line.
 */
struct AuthorizedKeyOptions {
	std::string command;

	bool no_port_forwarding = false;

	bool no_pty = false;

	/**
	 * Mount the home directory read-only?
	 *
	 * (This is a proprietary Lukko option.)
	 */
	bool home_read_only = false;

	/**
	 * @return true if the option was applied, false if the option
	 * is not supported
	 */
	bool Set(std::string_view name, std::string &&value) noexcept;

	/**
	 * Apply the restrictions of the given instance to this one.
	 * This can only add restrictions, never remove any; that
	 * makes it safe to apply restrictions received from another
	 * server.
	 *
	 * @return false if #other contains a "command" which
	 * contradicts the existing one (applying it would lift the
	 * existing restriction)
	 */
	bool Restrict(AuthorizedKeyOptions &&other) noexcept;
};
