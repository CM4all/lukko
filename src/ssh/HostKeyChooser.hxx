// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <string_view>

class SecretKey;

namespace SSH {

class HostKeyChooser {
public:
	/**
	 * Returns a comma-separated list of available/supported host
	 * key algorithms (for the KEXINIT packet).
	 */
	[[gnu::pure]]
	virtual std::string_view GetServerHostKeyAlgorithms() const noexcept = 0;

	/**
	 * Choose a host key (server mode only).
	 *
	 * @param algorithms a comma-separated list of key algorithms
	 * supported by the client
	 *
	 * @return the host key and the algorithm name
	 */
	[[gnu::pure]]
	virtual std::pair<const SecretKey *, std::string_view> ChooseHostKey([[maybe_unused]] std::string_view algorithms) const noexcept = 0;
};

} // namespace SSH
