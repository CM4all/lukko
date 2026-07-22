// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "HostKeyChooser.hxx"

class SecretKeyList;

namespace SSH {

/**
 * A #HostKeyChooser implementation that maps a #SecretKeyList.
 */
class SimpleHostKeyChooser final : public HostKeyChooser {
	const SecretKeyList &keys;

public:
	[[nodiscard]]
	explicit SimpleHostKeyChooser(const SecretKeyList &_keys) noexcept
		:keys(_keys) {}

	/* virtual methods from class SSH::HostKeyChooser */
	std::string_view GetServerHostKeyAlgorithms() const noexcept override;
	std::pair<const SecretKey *, std::string_view> ChooseHostKey(std::string_view algorithms) const noexcept override;
};

} // namespace SSH
