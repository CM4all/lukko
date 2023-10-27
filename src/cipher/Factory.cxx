// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Factory.hxx"
#include "ChaCha20Poly1305Cipher.hxx"
#include "util/IterableSplitString.hxx"

using std::string_view_literals::operator""sv;

namespace SSH {

class Cipher;

std::unique_ptr<Cipher>
MakeCipher(std::string_view algorithms,
	   std::span<const std::byte> key,
	   [[maybe_unused]] std::span<const std::byte> iv)
{
	for (const std::string_view a : IterableSplitString(algorithms, ','))
		if (a == "chacha20-poly1305@openssh.com"sv)
			return std::make_unique<ChaCha20Poly1305Cipher>(key);

	return {};
}

} // namespace SSH
