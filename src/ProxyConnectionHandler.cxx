// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "ProxyConnectionHandler.hxx"
#include "ProxyCheck.hxx"
#include "ssh/Connection.hxx"

using std::string_view_literals::operator""sv;

ProxyConnectionHandler::ProxyConnectionHandler(SSH::Connection &_source,
					       SSH::Connection &_target) noexcept
	:target(_target)
{
	_source.AddHandler(*this);
}

bool
ProxyConnectionHandler::HandlePacket(SSH::MessageNumber msg,
				     std::span<const std::byte> payload)
{
	if (ShouldProxy(msg)) {
		target.SendPacket(msg, payload);
		return true;
	} else
		return false;
}
