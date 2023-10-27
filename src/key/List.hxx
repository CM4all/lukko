// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <forward_list>
#include <map>
#include <memory>
#include <string>

class SecretKey;

class SecretKeyList {
	std::forward_list<std::unique_ptr<SecretKey>> keys;
	std::map<std::string_view, const SecretKey *> algorithm_to_key;

	std::string algorithms;

public:
	SecretKeyList() noexcept;
	~SecretKeyList() noexcept;

	SecretKeyList(SecretKeyList &&) noexcept = default;
	SecretKeyList &operator=(SecretKeyList &&) noexcept = default;

	bool empty() const noexcept {
		return keys.empty();
	}

	void Add(std::unique_ptr<SecretKey> key) noexcept;

	/**
	 * @return a comma-separated list of available server host key
	 * algorithms
	 */
	std::string_view GetAlgorithms() const noexcept {
		return algorithms;
	}

	/**
	 * Choose a host key based on the list of algorithms received
	 * in KEXINIT from the peer.
	 *
	 * @param peer_algorithms the "server_host_key_algorithms"
	 * string from the peer's KEXINIT packet, i.e. a
	 * comma-separated list of acceptable server host key
	 * algorithms
	 */
	[[gnu::pure]]
	std::pair<const SecretKey *, std::string_view> Choose(std::string_view peer_algorithms) const noexcept;
};
