// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <memory>
#include <span>

class SecretKey;

std::unique_ptr<SecretKey>
ParseSecretKey(std::span<const std::byte> src);
