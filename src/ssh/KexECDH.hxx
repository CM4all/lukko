// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "KexInterface.hxx"
#include "lib/openssl/UniqueEVP.hxx"

namespace SSH {

class Serializer;

class ECDHKex final : public Kex {
	const UniqueEVP_PKEY key;

public:
	ECDHKex();
	~ECDHKex() noexcept override;

	void MakeReply(std::span<const std::byte> client_ephemeral_public_key,
		       Serializer &server_ephemeral_public_key,
		       Serializer &shared_secret) override;
};

} // namespace SSH
