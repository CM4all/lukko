// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <cstddef>
#include <span>

class Serializer;

static constexpr std::size_t CURVE25519_SECRET_KEY_SIZE = 32;
static constexpr std::size_t CURVE25519_PUBLIC_KEY_SIZE = 32;
static constexpr std::size_t CURVE25519_SHARED_KEY_SIZE = 32;

/**
 * Calculate the X25519 public key for the specified secret key.
 *
 * Throws on error.
 */
void
Curve25519SecretKeyToPublicKey(std::span<const std::byte, CURVE25519_SECRET_KEY_SIZE> key,
			       std::span<std::byte, CURVE25519_PUBLIC_KEY_SIZE> pub);

/**
 * Calculate the raw X25519 shared secret.
 *
 * Throws on error (e.g. if the shared secret is all zero).
 */
void
Curve25519CalcSharedKey(std::span<const std::byte, CURVE25519_SECRET_KEY_SIZE> key,
			std::span<const std::byte, CURVE25519_PUBLIC_KEY_SIZE> pub,
			std::span<std::byte, CURVE25519_SHARED_KEY_SIZE> shared_key);
