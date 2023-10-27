// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "lib/openssl/UniqueEVP.hxx"

#include <cstddef>
#include <span>

UniqueEVP_PKEY
DeserializeECPublic(std::string_view curve_name, std::span<const std::byte> q);

UniqueEVP_PKEY
DeserializeEC(std::string_view curve_name, std::span<const std::byte> q,
	      std::span<const std::byte> d);
