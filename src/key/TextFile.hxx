// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <span>
#include <string_view>

class PublicKeySet;
class FileDescriptor;

void
LoadPublicKeysTextFile(PublicKeySet &set, FileDescriptor fd);

[[gnu::pure]]
bool
PublicKeysTextFileContains(std::string_view contents,
			   std::span<const std::byte> public_key_blob) noexcept;

[[gnu::pure]]
bool
PublicKeysTextFileContains(FileDescriptor fd,
			   std::span<const std::byte> public_key_blob) noexcept;
