// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "TextFile.hxx"
#include "Set.hxx"
#include "lib/sodium/Base64.hxx"
#include "io/BufferedReader.hxx"
#include "io/FdReader.hxx"
#include "util/AllocatedArray.hxx"
#include "util/CharUtil.hxx"
#include "util/IterableSplitString.hxx"
#include "util/SpanCast.hxx"
#include "util/StringSplit.hxx"
#include "util/StringStrip.hxx"
#include "config.h"

#include <stdexcept>
#include <tuple> // for std::tie()

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

static constexpr bool
IsOptionNameStartChar(char ch) noexcept
{
	return IsLowerAlphaASCII(ch);
}

static constexpr bool
IsOptionNameMiddleChar(char ch) noexcept
{
	return IsLowerAlphaASCII(ch) || ch == '-';
}

static constexpr std::pair<std::string_view, std::string_view>
ParseOptionName(std::string_view s) noexcept
{
	const char *p = s.data();
	const char *const end = p + s.size();

	if (s.empty() || !IsOptionNameStartChar(*p))
		return {};

	++p;
	while (true) {
		if (p == end)
			return {};

		if (!IsOptionNameMiddleChar(*p))
			return Partition(s, p);

		++p;
	}
}

static std::pair<std::string, std::string_view>
ParseOptionValue(std::string_view s) noexcept
{
	if (s.starts_with('"')) {
		s.remove_prefix(1);

		const char *p = s.data();
		const char *const end = p + s.size();

		std::string value;

		while (true) {
			if (p == end)
				return {};

			if (*p == '"')
				return {
					std::move(value),
					Partition(s, p + 1).second,
				};

			if (*p == '\\') {
				++p;
				if (p == end)
					return {};
			}

			value.push_back(*p);
			++p;
		}
	} else {
		const char *p = s.data();
		const char *const end = p + s.size();

		while (p != end) {
			if (*p == ',' || *p == ' ')
				break;

			++p;
		}

		auto [value, rest] = Partition(s, p);
		return {
			std::string{value},
			rest,
		};
	}
}

static std::string_view
ParseOptions(std::string_view s, AuthorizedKeyOptions &options) noexcept
{
	while (true) {
		auto [name, rest] = ParseOptionName(s);
		if (name.empty())
			return {};

		s = rest;

		std::string value;

		if (s.front() == '=')
			std::tie(value, s) = ParseOptionValue(s.substr(1));

		if (!options.Set(name, std::move(value)))
		    return {};

		if (s.empty())
			return {};

		if (s.front() == ' ')
			return StripLeft(s.substr(1));

		if (s.front() != ',')
			return {};

		s.remove_prefix(1);
	}
}

static std::pair<std::string_view, AuthorizedKeyOptions>
ExtractPublicKeyBlobFromLine(std::string_view line) noexcept
{
	line = StripLeft(line);
	if (line.empty() || line.front() == '#')
		return {};

	auto [key_type, rest] = Split(line, ' ');

	AuthorizedKeyOptions options;
	if (!MaybeSupportsKeyType(key_type)) {
		line = ParseOptions(line, options);
		std::tie(key_type, rest) = Split(line, ' ');
	}

	const auto [blob_b64, _] = Split(rest, ' ');
	return {blob_b64, std::move(options)};
}

static void
LoadPublicKeyLine(PublicKeySet &set, std::string_view line) noexcept
{
	if (auto [blob_base64, options] = ExtractPublicKeyBlobFromLine(line);
	    !blob_base64.empty()) {
		const auto blob = DecodeBase64(blob_base64);
		if (blob != nullptr)
			set.Add(blob, std::move(options));
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
static std::optional<AuthorizedKeyOptions>
PublicKeysTextLineContains(std::string_view line,
			   std::span<const std::byte> needle) noexcept
{
	if (const auto [blob_base64, options] = ExtractPublicKeyBlobFromLine(line);
	    !blob_base64.empty()) {
		const auto blob = DecodeBase64(blob_base64);
		if (blob == nullptr)
			return std::nullopt;

		if (!PublicKeyBlobsEqual(blob, needle))
			return std::nullopt;

		return std::move(options);
	} else
		return std::nullopt;
}

std::optional<AuthorizedKeyOptions>
PublicKeysTextFileContains(std::string_view contents,
			   std::span<const std::byte> needle) noexcept
{
	for (std::string_view line : IterableSplitString(contents, '\n'))
		if (auto options = PublicKeysTextLineContains(line, needle))
			return options;

	return std::nullopt;
}

static std::optional<AuthorizedKeyOptions>
PublicKeysTextFileContains(BufferedReader &r, std::span<const std::byte> needle)
{
	while (const char *line = r.ReadLine())
		if (auto options = PublicKeysTextLineContains(line, needle))
			return options;

	return std::nullopt;
}

std::optional<AuthorizedKeyOptions>
PublicKeysTextFileContains(FileDescriptor fd,
			   std::span<const std::byte> needle) noexcept
try {
	FdReader r{fd};
	BufferedReader br{r};
	return PublicKeysTextFileContains(br, needle);
} catch (...) {
	return std::nullopt;
}
