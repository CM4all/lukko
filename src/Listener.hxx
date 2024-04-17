// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "event/net/ServerSocket.hxx"
#include "net/SocketAddress.hxx"
#include "util/IntrusiveList.hxx"
#include "config.h"

#include <memory>
#include <string_view>

struct ListenerConfig;
class Instance;
class Connection;
class RootLogger;
class ClientAccountingMap;

class Listener final : ServerSocket {
	Instance &instance;

#ifdef ENABLE_TRANSLATION
	const std::string_view tag;
#endif // ENABLE_TRANSLATION

	const SocketAddress proxy_to;

	const RootLogger &logger;

	std::unique_ptr<ClientAccountingMap> client_accounting;

	IntrusiveList<Connection> connections;

public:
	Listener(Instance &_instance, const ListenerConfig &_config);
	~Listener() noexcept;

#ifdef ENABLE_TRANSLATION
	std::string_view GetTag() const noexcept {
		return tag;
	}
#endif // ENABLE_TRANSLATION

	SocketAddress GetProxyTo() const noexcept {
		return proxy_to;
	}

	using ServerSocket::GetLocalAddress;

#ifdef ENABLE_TRANSLATION
	void TerminateChildren(std::string_view child_tag) noexcept;
#endif

private:
	/* virtual methods from class ServerSocket */
	void OnAccept(UniqueSocketDescriptor fd,
		      SocketAddress address) noexcept override;
	void OnAcceptError(std::exception_ptr ep) noexcept override;
};
