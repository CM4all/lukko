// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "KexInterface.hxx"
#include "lib/openssl/UniqueEVP.hxx"

namespace SSH {

class Serializer;

class ECDHKex final : public Kex {
	const UniqueEVP_PKEY key;

public:
	ECDHKex();
	~ECDHKex() noexcept override;

	void SerializeEphemeralPublicKey(Serializer &s) const override;
	void GenerateSharedSecret(std::span<const std::byte> client_ephemeral_public_key,
				  Serializer &s) override;
};

} // namespace SSH
