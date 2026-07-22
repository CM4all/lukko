// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "HostKeyVerifier.hxx"

class PublicKeySet;

namespace SSH {

/**
 * A #HostKeyVerifier implementation that maps a #PublicKeySet.
 */
class SimpleHostKeyVerifier final : public HostKeyVerifier {
	const PublicKeySet &keys;

public:
	[[nodiscard]]
	explicit SimpleHostKeyVerifier(const PublicKeySet &_keys) noexcept
		:keys(_keys) {}

	/* virtual methods from class SSH::HostKeyVerifier */
	bool VerifyHostKey(std::span<const std::byte> server_host_key_blob) const noexcept override;
};

} // namespace SSH
