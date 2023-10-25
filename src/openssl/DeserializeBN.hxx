// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "lib/openssl/UniqueBN.hxx"

#include <cstddef>
#include <span>

UniqueBIGNUM<true>
DeserializeBIGNUM(std::span<const std::byte> src);
