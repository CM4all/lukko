// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "ssh/Connection.hxx"
#include "util/IntrusiveList.hxx"

class Instance;
class RootLogger;

namespace SSH {
class PacketSerializer;
}

class Connection final
	: public AutoUnlinkIntrusiveListHook,
	  SSH::Connection
{
	Instance &instance;
	const RootLogger &logger;

public:
	Connection(Instance &_instance, UniqueSocketDescriptor fd,
		   const Key &_host_key);
	~Connection() noexcept;

protected:
	void Destroy() noexcept override {
		delete this;
	}

private:
	void HandleServiceRequest(std::span<const std::byte> payload);
	void HandleUserauthRequest(std::span<const std::byte> payload);
	void HandleChannelOpen(std::span<const std::byte> payload);

	void HandlePacket(SSH::MessageNumber msg,
			  std::span<const std::byte> payload) override;

	/* virtual methods from class BufferedSocketHandler */
	void OnBufferedError(std::exception_ptr e) noexcept override;
};
