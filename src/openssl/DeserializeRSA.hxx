// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "lib/openssl/UniqueEVP.hxx"

#include <cstddef>
#include <span>

UniqueEVP_PKEY
DeserializeRSAPublic(std::span<const std::byte> e,
		     std::span<const std::byte> n);

UniqueEVP_PKEY
DeserializeRSA(std::span<const std::byte> n,
	       std::span<const std::byte> e,
	       std::span<const std::byte> d,
	       std::span<const std::byte> iqmp,
	       std::span<const std::byte> p,
	       std::span<const std::byte> q);
