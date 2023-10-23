// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "lib/openssl/UniqueEC.hxx"

#include <cstddef>
#include <span>

UniqueEC_KEY
DeserializeEC(int curve_nid, std::span<const std::byte> q,
	      std::span<const std::byte> d);
