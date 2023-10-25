// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <span>
#include <string_view>

namespace SSH { class Serializer; }

class Key {
public:
	Key() noexcept = default;
	virtual ~Key() noexcept = default;

	Key(const Key &) = delete;
	Key &operator=(const Key &) = delete;

	virtual std::string_view GetAlgorithm() const noexcept = 0;
	virtual void SerializeKex(SSH::Serializer &s) const = 0;
	virtual void Sign(SSH::Serializer &s, std::span<const std::byte> src) const = 0;
};
