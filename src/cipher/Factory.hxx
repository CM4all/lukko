// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <memory>
#include <span>

namespace SSH {

constexpr std::string_view all_encryption_algorithms{
	"chacha20-poly1305@openssh.com"
};

class Cipher;

/**
 * Construct a new stream cipher.
 *
 * Throws on error.
 *
 * @return the new #Cipher instance
 */
std::unique_ptr<Cipher>
MakeCipher(std::span<const std::byte> key, std::span<const std::byte> iv);

} // namespace SSH
