// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "ssh/Handler.hxx"

namespace SSH { class Connection; }

class ProxyConnectionHandler final : SSH::ConnectionHandler {
	SSH::Connection &source, &target;

	ProxyConnectionHandler *other = nullptr;

public:
	[[nodiscard]]
	explicit ProxyConnectionHandler(SSH::Connection &_source,
					SSH::Connection &_target) noexcept;

	void SetOther(ProxyConnectionHandler &_other) noexcept {
		other = &_other;
	}

private:
	void OnOtherWriteBlocked() noexcept;
	void OnOtherWriteUnblocked() noexcept;

	/* virtual methods from class ConnectionHandler */
	bool HandlePacket(SSH::MessageNumber msg,
			  std::span<const std::byte> payload) override;
	void OnWriteBlocked() noexcept override;
	void OnWriteUnblocked() noexcept override;
};
