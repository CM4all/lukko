// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "event/net/ServerSocket.hxx"
#include "net/SocketAddress.hxx"
#include "util/IntrusiveList.hxx"
#include "config.h"

#ifdef ENABLE_POND
#include "net/UniqueSocketDescriptor.hxx"
#endif

#include <memory>
#include <string_view>

struct ListenerConfig;
class Instance;
class DelayedConnection;
class Connection;
class RootLogger;
class ClientAccountingMap;

class Listener final : ServerSocket {
	friend class DelayedConnection;

	Instance &instance;

#ifdef ENABLE_TRANSLATION
	const std::string_view tag;
#endif // ENABLE_TRANSLATION

	const SocketAddress proxy_to;

#ifdef ENABLE_POND
	const UniqueSocketDescriptor pond_socket;
#endif

	const RootLogger &logger;

	std::unique_ptr<ClientAccountingMap> client_accounting;

	IntrusiveList<Connection> connections;
	IntrusiveList<DelayedConnection> delayed_connections;

	const bool verbose_errors, exec_reject_stderr;

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

	bool GetVerboseErrors() const noexcept {
		return verbose_errors;
	}

	bool GetExecRejectStderr() const noexcept {
		return exec_reject_stderr;
	}

#ifdef ENABLE_POND
	SocketDescriptor GetPondSocket() const noexcept {
		return pond_socket;
	}
#endif

	using ServerSocket::GetSocket;

#ifdef ENABLE_TRANSLATION
	void TerminateChildren(std::string_view child_tag) noexcept;
#endif

	struct Stats {
		std::size_t n_connections = 0;

		constexpr Stats &operator+=(const Stats &other) noexcept {
			n_connections += other.n_connections;
			return *this;
		}
	};

	Stats GetStats() const noexcept {
		return {
			.n_connections = connections.size(),
		};
	}

private:
	/* virtual methods from class ServerSocket */
	void OnAccept(UniqueSocketDescriptor fd,
		      SocketAddress address) noexcept override;
	void OnAcceptError(std::exception_ptr ep) noexcept override;
};
