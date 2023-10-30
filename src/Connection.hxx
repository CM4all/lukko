// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "ssh/CConnection.hxx"
#include "util/IntrusiveList.hxx"
#include "config.h"

#include <memory>

struct TranslateResponse;
class Instance;
class Listener;
class RootLogger;
class UniqueFileDescriptor;
class SpawnService;

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

#ifdef ENABLE_TRANSLATION
	struct Translation;
	std::unique_ptr<Translation> translation;
#endif // ENABLE_TRANSLATION

public:
	Connection(Instance &_instance, Listener &_listener,
		   UniqueSocketDescriptor fd,
		   const SecretKeyList &_host_keys);
	~Connection() noexcept;

	[[gnu::const]]
	SpawnService &GetSpawnService() const noexcept;

	Listener &GetListener() const noexcept {
		return listener;
	}

	std::string_view GetUsername() const noexcept {
		return username;
	}

#ifdef ENABLE_TRANSLATION
	[[gnu::pure]]
	const TranslateResponse *GetTranslationResponse() const noexcept;
#endif

	[[gnu::pure]]
	bool IsSftpOnly() const noexcept;

	[[gnu::pure]]
	bool IsExecAllowed() const noexcept {
		return !IsSftpOnly();
	}

	[[gnu::pure]]
	bool IsForwardingAllowed() const noexcept;

protected:
	void Destroy() noexcept override {
		delete this;
	}

private:
	[[gnu::pure]]
	const char *GetHome() const noexcept;
	UniqueFileDescriptor OpenHome() const noexcept;

	[[gnu::pure]]
	bool IsAcceptedPublicKey(std::span<const std::byte> public_key_blob) noexcept;

	void HandleServiceRequest(std::span<const std::byte> payload);
	void HandleUserauthRequest(std::span<const std::byte> payload);
	void HandleChannelOpen(std::span<const std::byte> payload);

	/* virtual methods from class SSH::CConnection */
	std::unique_ptr<SSH::Channel> OpenChannel(std::string_view channel_type,
						  SSH::ChannelInit init,
						  std::span<const std::byte> payload) override;

	/* virtual methods from class SSH::Connection */
	void HandlePacket(SSH::MessageNumber msg,
			  std::span<const std::byte> payload) override;

	/* virtual methods from class BufferedSocketHandler */
	void OnBufferedError(std::exception_ptr e) noexcept override;
};
