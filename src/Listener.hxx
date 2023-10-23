// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "event/net/ServerSocket.hxx"
#include "config.h"

struct ListenerConfig;
class Instance;
class RootLogger;

class Listener final : ServerSocket {
	Instance &instance;

#ifdef ENABLE_TRANSLATION
	const std::string_view tag;
#endif // ENABLE_TRANSLATION

	const RootLogger &logger;

public:
	Listener(Instance &_instance, const ListenerConfig &_config);

#ifdef ENABLE_TRANSLATION
	std::string_view GetTag() const noexcept {
		return tag;
	}
#endif // ENABLE_TRANSLATION

	using ServerSocket::GetLocalAddress;

private:
	/* virtual methods from class ServerSocket */
	void OnAccept(UniqueSocketDescriptor &&fd,
		      SocketAddress address) noexcept override;
	void OnAcceptError(std::exception_ptr ep) noexcept override;
};
