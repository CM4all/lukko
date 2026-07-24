// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "ProxyConnectionHandler.hxx"
#include "ProxyCheck.hxx"
#include "ssh/Connection.hxx"

using std::string_view_literals::operator""sv;

ProxyConnectionHandler::ProxyConnectionHandler(SSH::Connection &_source,
					       SSH::Connection &_target) noexcept
	:source(_source), target(_target)
{
	_source.AddHandler(*this);
}

inline void
ProxyConnectionHandler::OnOtherWriteBlocked() noexcept
{
	/* backpressure */
	source.BlockRead();
}

inline void
ProxyConnectionHandler::OnOtherWriteUnblocked() noexcept
{
	source.UnblockRead();
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

void
ProxyConnectionHandler::OnWriteBlocked() noexcept
{
	if (other)
		other->OnOtherWriteBlocked();
}

void
ProxyConnectionHandler::OnWriteUnblocked() noexcept
{
	if (other)
		other->OnOtherWriteUnblocked();
}
