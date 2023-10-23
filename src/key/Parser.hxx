// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstddef>
#include <memory>
#include <span>

class Key;

std::unique_ptr<Key>
ParseKey(std::span<const std::byte> src);
