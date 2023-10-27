// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Key.hxx"

#include <array>

class Ed25519Key final : public SecretKey {
	std::array<std::byte, 32> public_key;
	std::array<std::byte, 64> secret_key;

public:
	struct Generate{};
	explicit Ed25519Key(Generate) noexcept;

	Ed25519Key(std::span<const std::byte, 32> _public_key,
		   std::span<const std::byte, 64> _secret_key) noexcept;

	~Ed25519Key() noexcept override;

	std::string_view GetType() const noexcept override;
	std::string_view GetAlgorithms() const noexcept override;
	void SerializePublic(SSH::Serializer &s) const override;
	bool Verify(std::span<const std::byte> message,
		    std::span<const std::byte> signature) const override;
	void Sign(SSH::Serializer &s, std::span<const std::byte> src,
		  std::string_view algorithm) const override;
};
