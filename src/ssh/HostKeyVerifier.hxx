// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <cstddef>
#include <span>

namespace SSH {

class HostKeyVerifier {
public:
	/**
	 * Check whether the give host key is acceptable.
	 *
	 * @return true to accept the host key
	 */
	[[gnu::pure]]
	virtual bool VerifyHostKey(std::span<const std::byte> server_host_key_blob) const noexcept = 0;
};

} // namespace SSH
