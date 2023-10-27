// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Factory.hxx"
#include "ChaCha20Poly1305Cipher.hxx"

namespace SSH {

class Cipher;

std::unique_ptr<Cipher>
MakeCipher(std::span<const std::byte> key,
	   [[maybe_unused]] std::span<const std::byte> iv)
{
	return std::make_unique<ChaCha20Poly1305Cipher>(key);
}

} // namespace SSH
