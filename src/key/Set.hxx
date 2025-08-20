// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <cstddef>
#include <map>
#include <span>
#include <string>

struct AuthorizedKeyOptions;
class PublicKey;

/**
 * Manages a set of public keys and can check whether the set contains
 * a certain key.  This is used for the list of authorized keys.
 * Internally, it stores the serialized BLOBs of each public key.
 */
class PublicKeySet {
	std::map<std::string, AuthorizedKeyOptions, std::less<>> keys;

public:
	PublicKeySet() noexcept;
	PublicKeySet(PublicKeySet &&src) noexcept;
	~PublicKeySet() noexcept;

	void Add(std::span<const std::byte> blob,
		 AuthorizedKeyOptions &&options) noexcept;
	void Add(const PublicKey &key) noexcept;

	[[gnu::pure]]
	const AuthorizedKeyOptions *Find(std::span<const std::byte> blob) const noexcept;

	[[gnu::pure]]
	const AuthorizedKeyOptions *Find(const PublicKey &key) const noexcept;
};
