// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "KexState.hxx"
#include "cipher/Cipher.hxx"
#include "cipher/Factory.hxx"

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
		     Role role,
		     bool kex_initial)
{
	if (kex_initial) {
		/* RFC 4253 section 9: "Re-exchange is processed
		   identically to the initial key exchange, except for
		   the session identifier that will remain
		   unchanged" */
		if (session_id.empty())
			session_id = hash;
	} else {
		if (session_id.empty())
			throw std::runtime_error{"No session ID"};
	}

	std::array<AllocatedArray<std::byte>, 6> keys;

	char id = 'A';
	for (auto &i : keys)
		i = DeriveKey(id++, we_need, hash, shared_secret, session_id, hash_alg);

	for (std::size_t i = 0; i < new_keys.size(); ++i) {
		const Direction direction = static_cast<Direction>(i);
		const bool ctos = (role != Role::SERVER && direction == Direction::OUTGOING) ||
			(role == Role::SERVER && direction == Direction::INCOMING);
		new_keys[i].enc_iv = std::move(keys[ctos ? 0 : 1]);
		new_keys[i].enc_key = std::move(keys[ctos ? 2 : 3]);
		new_keys[i].mac_key = std::move(keys[ctos ? 4 : 5]);
	}
}

std::unique_ptr<Cipher>
KexState::MakeCipher(std::string_view encryption_algorithms,
		     std::string_view mac_algorithms,
		     Direction direction)
{
	const auto &k = new_keys[static_cast<std::size_t>(direction)];

	return SSH::MakeCipher(encryption_algorithms, mac_algorithms,
			       k.enc_key, k.enc_iv, k.mac_key,
			       direction == Direction::OUTGOING);
}

} // namespace SSH
