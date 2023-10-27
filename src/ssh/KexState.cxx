// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "KexState.hxx"
#include "cipher/ChaCha20Poly1305Cipher.hxx"

#include <stdexcept>

namespace SSH {

static AllocatedArray<std::byte>
DeriveKey(const char id, std::size_t need,
	  std::span<const std::byte> hash,
	  std::span<const std::byte> shared_secret,
	  std::span<const std::byte> session_id,
	  DigestAlgorithm hash_alg)
{
	std::array<std::byte, DIGEST_MAX_SIZE> digest_buffer;
	assert(need <= digest_buffer.size());

	std::size_t digest_size = Digest(hash_alg,
					 {shared_secret, hash, std::as_bytes(std::span{&id, 1}), session_id},
					 digest_buffer.data());

	std::size_t position = digest_size;
	while (position < need) {
		digest_size = Digest(hash_alg,
				     {shared_secret, hash, std::span{digest_buffer}.first(position)},
				     digest_buffer.data() + position);
		position += digest_size;
	}

	return AllocatedArray<std::byte>{std::span{digest_buffer}.first(position)};
}

void
KexState::DeriveKeys(std::span<const std::byte> hash,
		     std::span<const std::byte> shared_secret,
		     bool kex_initial)
{
	if (kex_initial) {
		if (!session_id.empty())
			throw std::runtime_error{"Duplicate session ID"};

		session_id = hash;
	} else {
		if (session_id.empty())
			throw std::runtime_error{"No session ID"};
	}

	std::array<AllocatedArray<std::byte>, 6> keys;

	char id = 'A';
	for (auto &i : keys)
		i = DeriveKey(id++, we_need, hash, shared_secret, session_id, hash_alg);

	for (unsigned mode = 0; mode < new_keys.size(); ++mode) {
		const bool ctos = (!is_server && mode == MODE_OUT) ||
		    (is_server && mode == MODE_IN);
		new_keys[mode].enc_iv = std::move(keys[ctos ? 0 : 1]);
		new_keys[mode].enc_key = std::move(keys[ctos ? 2 : 3]);
		new_keys[mode].mac_key = std::move(keys[ctos ? 4 : 5]);
	}
}

std::unique_ptr<Cipher>
KexState::MakeCipher(kex_modes mode)
{
	const auto &k = new_keys[mode];

	return std::make_unique<ChaCha20Poly1305Cipher>(k.enc_key, k.enc_iv);
}

} // namespace SSH
