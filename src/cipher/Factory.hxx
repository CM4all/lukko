// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "config.h"

#include <cstddef>
#include <memory>
#include <span>
#include <string_view>

namespace SSH {

constexpr std::string_view all_encryption_algorithms{
	"chacha20-poly1305@openssh.com"
#ifdef HAVE_OPENSSL
	",aes128-ctr,aes192-ctr,aes256-ctr"
	",aes128-gcm@openssh.com,aes256-gcm@openssh.com"
#endif
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
	   std::span<const std::byte> key, std::span<const std::byte> iv,
	   bool do_encrypt);

} // namespace SSH
