// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "lib/sodium/Curve25519Types.hxx"

class Serializer;

/**
 * Calculate the X25519 public key for the specified secret key.
 *
 * Throws on error.
 */
void
Curve25519SecretKeyToPublicKey(Curve25519ScalarView key, Curve25519Ptr pub);

/**
 * Calculate the raw X25519 shared secret.
 *
 * Throws on error (e.g. if the shared secret is all zero).
 */
void
Curve25519CalcSharedKey(Curve25519ScalarView key, Curve25519View pub,
			Curve25519Ptr shared_key);
