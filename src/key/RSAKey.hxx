// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Key.hxx"
#include "lib/openssl/UniqueEVP.hxx"

class RSAKey final : public SecretKey {
	UniqueEVP_PKEY key;

public:
	struct Generate {};
	explicit RSAKey(Generate);

	explicit RSAKey(UniqueEVP_PKEY &&_key) noexcept
		:key(std::move(_key)) {}

	std::string_view GetAlgorithm() const noexcept override;
	void SerializePublic(SSH::Serializer &s) const override;
	bool Verify(std::span<const std::byte> message,
		    std::span<const std::byte> signature) const override;
	void Sign(SSH::Serializer &s, std::span<const std::byte> src) const override;
};
