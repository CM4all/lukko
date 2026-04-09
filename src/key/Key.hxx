// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <cstddef>
#include <span>
#include <string_view>

namespace SSH { class Serializer; }

/**
 * A public key for use with SSH authentication.
 */
class PublicKey {
public:
	PublicKey() noexcept = default;
	virtual ~PublicKey() noexcept = default;

	PublicKey(const PublicKey &) = delete;
	PublicKey &operator=(const PublicKey &) = delete;

	/**
	 * Returns the SSH key type string, e.g. "ssh-ed25519" or
	 * "ssh-rsa".
	 */
	virtual std::string_view GetType() const noexcept = 0;

	/**
	 * Returns a comma-separated list of signature algorithms
	 * (formats) supported by this key.
	 *
	 * @see RFC 4253 6.6
	 * @see RFC 4253 7.1
	 */
	virtual std::string_view GetAlgorithms() const noexcept = 0;

	/**
	 * Serialize the public key part.
	 *
	 * @see RFC 4253 6.6
	 */
	virtual void SerializePublic(SSH::Serializer &s) const = 0;

	/**
	 * Verify whether the signature for the specified message
	 * belongs matches this public key.
	 *
	 * Throws on error (e.g. protocol error).
	 *
	 * @return true if the signature matches this key, false on
	 * mismatch
	 */
	virtual bool Verify(std::span<const std::byte> message,
			    std::span<const std::byte> signature) const = 0;
};

/**
 * A secret (private) key for use with SSH.
 */
class SecretKey : public PublicKey {
public:
	SecretKey() noexcept = default;
	virtual ~SecretKey() noexcept = default;

	SecretKey(const SecretKey &) = delete;
	SecretKey &operator=(const SecretKey &) = delete;

	/**
	 * Sign a message.
	 *
	 * Throws on error (e.g. unsupported algorithm).
	 *
	 * @param s a #Serializer the signature will be written to
	 * @param src the message to be signed
	 * @param algorithm the algorithm (format) to be used; must be
	 * one of the algorithms returned by GetAlgorithms()
	 */
	virtual void Sign(SSH::Serializer &s, std::span<const std::byte> src,
			  std::string_view algorithm) const = 0;
};
