// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "ssh/Disposer.hxx"
#include "event/net/ServerSocket.hxx"
#include "net/SocketAddress.hxx"
#include "util/IntrusiveList.hxx"
#include "config.h"

#ifdef ENABLE_POND
#include "net/UniqueSocketDescriptor.hxx"
#endif

#include <memory>
#include <string_view>
#include <variant>

struct ListenerConfig;
struct TargetHostConfig;
class Instance;
class DelayedConnection;
class Connection;
class RootLogger;
class ClientAccountingMap;
class PublicKeySet;
class SecretKeyList;
namespace Avahi { struct Service; }

enum class Arch : uint_least8_t;

#ifdef HAVE_AVAHI
#include <cstddef>
#include <span>
class ZeroconfCluster;
#endif

class Listener final
	: ServerSocket,
	  public SSH::ConnectionDisposer
{
	friend class DelayedConnection;

public:
	using ProxyTo = std::variant<std::monostate,
#ifdef HAVE_AVAHI
				     ZeroconfCluster *,
#endif
				     const TargetHostConfig *>;

private:
	Instance &instance;

#ifdef ENABLE_TRANSLATION
	const std::string_view tag;
#endif // ENABLE_TRANSLATION

	const SecretKeyList &host_keys;
	const PublicKeySet &authorized_host_keys;

	const ProxyTo proxy_to;

	const PublicKeySet *const proxy_host_keys;

#ifdef ENABLE_POND
	const UniqueSocketDescriptor pond_socket;
#endif

	const RootLogger &logger;

#ifdef HAVE_AVAHI
	const std::unique_ptr<Avahi::Service> avahi_service;
#endif

	std::unique_ptr<ClientAccountingMap> client_accounting;

	IntrusiveList<Connection> connections;
	IntrusiveList<DelayedConnection> delayed_connections;

	const bool send_client_address, accept_client_address;

	const bool verbose_errors, exec_reject_stderr;

public:
	Listener(Instance &_instance, const ListenerConfig &_config);
	~Listener() noexcept;

#ifdef ENABLE_TRANSLATION
	std::string_view GetTag() const noexcept {
		return tag;
	}
#endif // ENABLE_TRANSLATION

	const SecretKeyList &GetHostKeys() const noexcept {
		return host_keys;
	}

	const PublicKeySet &GetAuthorizedHostKeys() const noexcept {
		return authorized_host_keys;
	}

	[[gnu::pure]]
	bool HasProxyTo() const noexcept {
		return !std::holds_alternative<std::monostate>(proxy_to);
	}

	bool IsArchSpecific() const noexcept {
		/* if we are proxying somewhere else, we're not arch
		   specific - our CPU architecture doesn't matter */
		return !HasProxyTo();
	}

#ifdef HAVE_AVAHI
	bool HasZeroconf() const noexcept {
		return avahi_service != nullptr;
	}
#endif // HAVE_AVAHI

	/**
	 * Throws on error.
	 */
	SocketAddress GetProxyTo(Arch arch, std::span<const std::byte> sticky_source) const;

	[[gnu::pure]]
	const PublicKeySet &GetProxyHostKeys() const noexcept {
		return *proxy_host_keys;
	}

	bool GetSendClientAddress() const noexcept {
		return send_client_address;
	}

	bool GetAcceptClientAddress() const noexcept {
		return accept_client_address;
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
	std::unique_ptr<Avahi::Service> MakeAvahiService(const ListenerConfig &config) const noexcept;

	/* virtual methods from class SSH::ConnectionDisposer */
	void Dispose(SSH::Connection *connection) noexcept override;

	/* virtual methods from class ServerSocket */
	void OnAccept(UniqueSocketDescriptor fd,
		      SocketAddress address) noexcept override;
	void OnAcceptError(std::exception_ptr ep) noexcept override;
};
