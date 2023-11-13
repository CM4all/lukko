// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Options.hxx"

#include <cstddef>
#include <optional>
#include <span>
#include <string_view>

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
