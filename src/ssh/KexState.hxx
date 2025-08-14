// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "Digest.hxx"
#include "util/AllocatedArray.hxx"

#include <array>
#include <memory>
#include <string_view>

namespace SSH {

class Cipher;

enum class Role : uint_least8_t {
	SERVER,
	CLIENT,
};

enum class Direction : uint_least8_t {
	INCOMING,
	OUTGOING,
};

struct KexState {
	struct NewKey {
		AllocatedArray<std::byte> enc_iv, enc_key, mac_key;
	};

	std::array<NewKey, 2> new_keys;

	AllocatedArray<std::byte> session_id;

	std::size_t we_need = 64; // TODO

	static constexpr DigestAlgorithm hash_alg = DigestAlgorithm::SHA256; // TODO

	void DeriveKeys(std::span<const std::byte> hash,
			std::span<const std::byte> shared_secret,
			Role role,
			bool kex_initial);

	std::unique_ptr<Cipher> MakeCipher(std::string_view encryption_algorithms,
					   std::string_view mac_algorithms,
					   Direction direction);
};

} // namespace SSH
