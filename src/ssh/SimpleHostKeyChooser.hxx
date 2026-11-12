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

/**
 * A base class with a #SimpleHostKeyChooser field.  This is a kludge
 * that allows passing the #SimpleHostKeyChooser to the constructor
 * of another base class (e.g. #Connection), as a workaround for
 * `-Wmaybe-uninitialized`.
 */
class WithSimpleHostKeyChooser {
protected:
	const SSH::SimpleHostKeyChooser host_key_chooser;

	explicit WithSimpleHostKeyChooser(const SecretKeyList &_keys) noexcept
		:host_key_chooser(_keys) {}
};

} // namespace SSH
