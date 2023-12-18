// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "KexInterface.hxx"

#include <array>

namespace SSH {

class Serializer;

class Curve25519Kex final : public Kex {
	std::array<std::byte, 32> secret_key;

public:
	Curve25519Kex();
	~Curve25519Kex() noexcept override;

	void MakeReply(std::span<const std::byte> client_ephemeral_public_key,
		       Serializer &server_ephemeral_public_key,
		       Serializer &shared_secret) override;
};

} // namespace SSH
