// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Digest.hxx"
#include "util/AllocatedArray.hxx"

#include <array>
#include <memory>

namespace SSH {

class Cipher;

enum kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

struct KexState {
	struct NewKey {
		AllocatedArray<std::byte> enc_iv, enc_key, mac_key;
	};

	std::array<NewKey, MODE_MAX> new_keys;

	AllocatedArray<std::byte> session_id;

	std::size_t we_need = 64; // TODO

	static constexpr DigestAlgorithm hash_alg = DigestAlgorithm::SHA256; // TODO

	static constexpr bool is_server = true;

	void DeriveKeys(std::span<const std::byte> hash,
			std::span<const std::byte> shared_secret,
			bool kex_initial);

	std::unique_ptr<Cipher> MakeCipher(kex_modes mode);
};

} // namespace SSH
