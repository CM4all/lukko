// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "Options.hxx"

#include <cstddef>
#include <optional>
#include <span>
#include <string_view>

static constexpr std::size_t MAX_PUBLIC_KEYS_TEXT_FILE_SIZE = 1024zu * 1024zu;

class PublicKeySet;
class FileDescriptor;

void
LoadPublicKeysTextFile(PublicKeySet &set, FileDescriptor fd);

[[gnu::pure]]
std::optional<AuthorizedKeyOptions>
PublicKeysTextFileContains(std::string_view contents,
			   std::span<const std::byte> public_key_blob) noexcept;

[[gnu::pure]]
std::optional<AuthorizedKeyOptions>
PublicKeysTextFileContains(FileDescriptor fd,
			   std::span<const std::byte> public_key_blob) noexcept;
