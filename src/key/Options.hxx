// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

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
	 * @return true if the option was applied, false if the option
	 * is not supported
	 */
	bool Set(std::string_view name, std::string &&value) noexcept;
};
