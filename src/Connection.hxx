// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "ssh/CConnection.hxx"
#include "util/IntrusiveList.hxx"

class Instance;
class Listener;
class RootLogger;

namespace SSH {
class PacketSerializer;
}

class Connection final
	: public AutoUnlinkIntrusiveListHook,
	  public SSH::CConnection
{
	Instance &instance;
	Listener &listener;
	const RootLogger &logger;

	std::string username;

public:
	Connection(Instance &_instance, Listener &_listener,
		   UniqueSocketDescriptor fd,
		   const KeyList &_host_keys);
	~Connection() noexcept;

	Listener &GetListener() const noexcept {
		return listener;
	}

	std::string_view GetUsername() const noexcept {
		return username;
	}

protected:
	void Destroy() noexcept override {
		delete this;
	}

private:
	void HandleServiceRequest(std::span<const std::byte> payload);
	void HandleUserauthRequest(std::span<const std::byte> payload);
	void HandleChannelOpen(std::span<const std::byte> payload);

	/* virtual methods from class SSH::CConnection */
	std::unique_ptr<SSH::Channel> OpenChannel(std::string_view channel_type,
						  SSH::ChannelInit init) override;

	/* virtual methods from class SSH::Connection */
	void HandlePacket(SSH::MessageNumber msg,
			  std::span<const std::byte> payload) override;

	/* virtual methods from class BufferedSocketHandler */
	void OnBufferedError(std::exception_ptr e) noexcept override;
};
