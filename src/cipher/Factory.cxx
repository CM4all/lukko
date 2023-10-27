// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Factory.hxx"
#include "ChaCha20Poly1305Cipher.hxx"
#include "util/IterableSplitString.hxx"

#ifdef HAVE_OPENSSL
#include "cipher/OsslCipher.hxx"
#include <openssl/evp.h>
#endif

using std::string_view_literals::operator""sv;

namespace SSH {

class Cipher;

std::unique_ptr<Cipher>
MakeCipher(std::string_view algorithms,
	   std::span<const std::byte> key,
	   [[maybe_unused]] std::span<const std::byte> iv,
	   [[maybe_unused]] bool do_encrypt)
{
	for (const std::string_view a : IterableSplitString(algorithms, ','))
		if (a == "chacha20-poly1305@openssh.com"sv)
			return std::make_unique<ChaCha20Poly1305Cipher>(key);
#ifdef HAVE_OPENSSL
		else if (a == "aes128-ctr"sv)
			return std::make_unique<OsslCipher>(*EVP_aes_128_ctr(),
							    16, 0,
							    key.first(16), iv,
							    do_encrypt);
		else if (a == "aes192-ctr"sv)
			return std::make_unique<OsslCipher>(*EVP_aes_192_ctr(),
							    16, 0,
							    key.first(24), iv,
							    do_encrypt);
		else if (a == "aes256-ctr"sv)
			return std::make_unique<OsslCipher>(*EVP_aes_256_ctr(),
							    16, 0,
							    key.first(32), iv,
							    do_encrypt);
		else if (a == "aes128-gcm@openssh.com"sv)
			return std::make_unique<OsslCipher>(*EVP_aes_128_gcm(),
							    16, 16,
							    key.first(16), iv.first(12),
							    do_encrypt);
		else if (a == "aes256-gcm@openssh.com"sv)
			return std::make_unique<OsslCipher>(*EVP_aes_256_gcm(),
							    16, 16,
							    key.first(32), iv.first(12),
							    do_encrypt);
#endif // HAVE_OPENSSL

	return {};
}

} // namespace SSH
