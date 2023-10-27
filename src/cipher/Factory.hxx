// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <string_view>

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
 * @return the new #Cipher instance or nullptr if there is no matching
 * cipher
 */
std::unique_ptr<Cipher>
MakeCipher(std::string_view algorithms,
	   std::span<const std::byte> key, std::span<const std::byte> iv);

} // namespace SSH
