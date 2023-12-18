// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <span>

namespace SSH {

class Serializer;

class Kex {
public:
	virtual void MakeReply(std::span<const std::byte> client_ephemeral_public_key,
			       Serializer &server_ephemeral_public_key,
			       Serializer &shared_secret) = 0;
};

} // namespace SSH
