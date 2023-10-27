// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "TextFile.hxx"
#include "Set.hxx"
#include "lib/sodium/Base64.hxx"
#include "io/BufferedReader.hxx"
#include "io/FdReader.hxx"
#include "util/AllocatedArray.hxx"
#include "util/IterableSplitString.hxx"
#include "util/SpanCast.hxx"
#include "util/StringSplit.hxx"
#include "util/StringStrip.hxx"
#include "config.h"

#include <stdexcept>

using std::string_view_literals::operator""sv;

static bool
MaybeSupportsKeyType(std::string_view key_type) noexcept
{
	return key_type.starts_with("ssh-"sv)
#ifdef HAVE_OPENSSL
		|| key_type.starts_with("ecdsa-"sv)
#endif
		;
}

static std::string_view
ExtractPublicKeyBlobFromLine(std::string_view line) noexcept
{
	line = StripLeft(line);
	if (line.empty() || line.front() == '#')
		return {};

	const auto [key_type, rest] = Split(line, ' ');
	const auto [blob_b64, _] = Split(rest, ' ');

	if (MaybeSupportsKeyType(key_type))
		return blob_b64;

	return {};
}

static void
LoadPublicKeyLine(PublicKeySet &set, std::string_view line) noexcept
{
	if (const auto blob_base64 = ExtractPublicKeyBlobFromLine(line);
	    !blob_base64.empty()) {
		const auto blob = DecodeBase64(blob_base64);
		if (blob != nullptr)
			set.Add(blob);
	}
}

static void
LoadPublicKeysTextFile(PublicKeySet &set, BufferedReader &r)
{
	while (const char *line = r.ReadLine())
		LoadPublicKeyLine(set, line);
}

void
LoadPublicKeysTextFile(PublicKeySet &set, FileDescriptor fd)
{
	FdReader r{fd};
	BufferedReader br{r};
	LoadPublicKeysTextFile(set, br);
}

[[gnu::pure]]
static bool
PublicKeyBlobsEqual(std::span<const std::byte> a,
		    std::span<const std::byte> b) noexcept
{
	return ToStringView(a) == ToStringView(b);
}

[[gnu::pure]]
static bool
PublicKeysTextLineContains(std::string_view line,
			   std::span<const std::byte> needle) noexcept
{
	if (const auto blob_base64 = ExtractPublicKeyBlobFromLine(line);
	    !blob_base64.empty()) {
		const auto blob = DecodeBase64(blob_base64);
		if (blob == nullptr)
			return false;

		return PublicKeyBlobsEqual(blob, needle);
	} else
		return false;
}

bool
PublicKeysTextFileContains(std::string_view contents,
			   std::span<const std::byte> needle) noexcept
{
	for (std::string_view line : IterableSplitString(contents, '\n'))
		if (PublicKeysTextLineContains(line, needle))
			return true;

	return false;
}

static bool
PublicKeysTextFileContains(BufferedReader &r, std::span<const std::byte> needle)
{
	while (const char *line = r.ReadLine())
		if (PublicKeysTextLineContains(line, needle))
			return true;

	return false;
}

bool
PublicKeysTextFileContains(FileDescriptor fd,
			   std::span<const std::byte> needle) noexcept
try {
	FdReader r{fd};
	BufferedReader br{r};
	return PublicKeysTextFileContains(br, needle);
} catch (...) {
	return false;
}
