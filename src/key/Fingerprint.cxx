// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Fingerprint.hxx"
#include "Key.hxx"
#include "ssh/Serializer.hxx"
#include "lib/sodium/Base64.hxx"
#include "lib/sodium/SHA256.hxx"
#include "util/AllocatedString.hxx"

#include <fmt/core.h>

using std::string_view_literals::operator""sv;

std::string
GetFingerprint(const PublicKey &key) noexcept
try {
	SSH::Serializer s;
	key.SerializePublic(s);

	const auto digest = SHA256(s.Finish());
	return fmt::format("SHA256:{}"sv, SodiumBase64(digest).c_str());
} catch (...) {
	// TODO log exception?
	return "ERROR";
}
