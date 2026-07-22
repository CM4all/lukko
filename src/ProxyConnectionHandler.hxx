// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "ssh/Handler.hxx"

namespace SSH { class Connection; }

class ProxyConnectionHandler final : SSH::ConnectionHandler {
	SSH::Connection &target;

public:
	[[nodiscard]]
	explicit ProxyConnectionHandler(SSH::Connection &_source,
					SSH::Connection &_target) noexcept;

private:
	/* virtual methods from class ConnectionHandler */
	bool HandlePacket(SSH::MessageNumber msg,
			  std::span<const std::byte> payload) override;
};
