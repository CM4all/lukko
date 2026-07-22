// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "SimpleHostKeyChooser.hxx"
#include "key/List.hxx"

namespace SSH {

std::string_view
SimpleHostKeyChooser::GetServerHostKeyAlgorithms() const noexcept
{
	return keys.GetAlgorithms();
}

std::pair<const SecretKey *, std::string_view>
SimpleHostKeyChooser::ChooseHostKey(std::string_view algorithms) const noexcept
{
	return keys.Choose(algorithms);
}

} // namespace SSH
