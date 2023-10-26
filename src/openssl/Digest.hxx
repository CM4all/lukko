// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "../Digest.hxx"

#include <openssl/evp.h>

[[gnu::const]]
inline const EVP_MD *
ToEvpMD(DigestAlgorithm a) noexcept
{
	switch (a) {
#ifdef HAVE_LIBMD
	case DigestAlgorithm::SHA1:
		return EVP_sha1();
#endif

	case DigestAlgorithm::SHA256:
		return EVP_sha256();

#ifdef HAVE_LIBMD
	case DigestAlgorithm::SHA384:
		return EVP_sha256();
#endif

	case DigestAlgorithm::SHA512:
		return EVP_sha512();
	}

	return nullptr;
}
