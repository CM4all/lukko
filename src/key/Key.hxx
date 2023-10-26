// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <span>
#include <string_view>

namespace SSH { class Serializer; }

class PublicKey {
public:
	PublicKey() noexcept = default;
	virtual ~PublicKey() noexcept = default;

	PublicKey(const PublicKey &) = delete;
	PublicKey &operator=(const PublicKey &) = delete;

	virtual std::string_view GetAlgorithm() const noexcept = 0;
	virtual void SerializePublic(SSH::Serializer &s) const = 0;
	virtual bool Verify(std::span<const std::byte> message,
			    std::span<const std::byte> signature) const = 0;
};

class SecretKey : public PublicKey {
public:
	SecretKey() noexcept = default;
	virtual ~SecretKey() noexcept = default;

	SecretKey(const SecretKey &) = delete;
	SecretKey &operator=(const SecretKey &) = delete;

	virtual void Sign(SSH::Serializer &s, std::span<const std::byte> src) const = 0;
};
