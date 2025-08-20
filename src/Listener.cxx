// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "Listener.hxx"
#include "Instance.hxx"
#include "Config.hxx"
#include "DelayedConnection.hxx"
#include "Connection.hxx"
#include "ssh/EarlyDisconnect.hxx"
#include "ssh/Protocol.hxx"
#include "lib/fmt/SocketAddressFormatter.hxx"
#include "net/ClientAccounting.hxx"
#include "net/SocketAddress.hxx"
#include "time/Cast.hxx"
#include "util/AlwaysFalse.hxx"
#include "util/DeleteDisposer.hxx"

#ifdef ENABLE_POND
#include "net/ConnectSocket.hxx"
#endif

#ifdef HAVE_AVAHI
#include "ZeroconfCluster.hxx"
#endif

#include <fmt/core.h>

#include <sys/socket.h>

using std::string_view_literals::operator""sv;

static Listener::ProxyTo
LoadProxyTo(Instance &instance, const ListenerConfig &config)
{
	return std::visit([&instance](const auto &value) -> Listener::ProxyTo {
		using T = std::decay_t<decltype(value)>;
		if constexpr (std::is_same_v<T, const TargetHostConfig *>) {
			return value;
#ifdef HAVE_AVAHI
		} else if constexpr (std::is_same_v<T, const ZeroconfClusterConfig *>) {
			return &instance.MakeZeroconfCluster(*value);
#else
			(void)instance;
#endif // HAVE_AVAHI
		} else if constexpr (std::is_same_v<T, std::monostate>) {
			return {};
		} else {
			static_assert(always_false_v<T>);
		}
        }, config.proxy_to);
}

[[gnu::pure]]
static const PublicKeySet *
LoadProxyHostKeys(const ListenerConfig &config) noexcept
{
	return std::visit([](const auto &value) -> const PublicKeySet * {
		using T = std::decay_t<decltype(value)>;
		if constexpr (std::is_same_v<T, std::monostate>)
			return nullptr;
		else
			return &value->host_keys;
        }, config.proxy_to);
}

Listener::Listener(Instance &_instance, const ListenerConfig &config)
	:ServerSocket(_instance.GetEventLoop(), config.Create(SOCK_STREAM)),
	 instance(_instance),
#ifdef ENABLE_TRANSLATION
	 tag(config.tag.empty() ? std::string_view{} : config.tag),
#endif
	 proxy_to(LoadProxyTo(instance, config)),
	 proxy_host_keys(LoadProxyHostKeys(config)),
#ifdef ENABLE_POND
	 pond_socket(!config.pond_server.IsNull()
		     ? CreateConnectDatagramSocket(config.pond_server)
		     : UniqueSocketDescriptor{}),
#endif
	 logger(instance.GetLogger()),
	 verbose_errors(config.verbose_errors),
	 exec_reject_stderr(config.exec_reject_stderr)
{
	assert(proxy_host_keys == nullptr || !proxy_host_keys->empty());

	if (config.max_connections_per_ip > 0 || config.tarpit)
		client_accounting = std::make_unique<ClientAccountingMap>(_instance.GetEventLoop(),
									  config.max_connections_per_ip,
									  config.tarpit);
}

Listener::~Listener() noexcept
{
	delayed_connections.clear_and_dispose(DeleteDisposer{});
	connections.clear_and_dispose(DeleteDisposer{});
}

SocketAddress
Listener::GetProxyTo(Arch arch, std::span<const std::byte> sticky_source) const
{
	return std::visit([arch, sticky_source](const auto &value) -> SocketAddress {
		using T = std::decay_t<decltype(value)>;
		if constexpr (std::is_same_v<T, const TargetHostConfig *>) {
			return value->address;
#ifdef HAVE_AVAHI
		} else if constexpr (std::is_same_v<T, ZeroconfCluster *>) {
			const SocketAddress address = value->Pick(arch, sticky_source);
			if (address.IsNull())
				throw std::runtime_error{"Zeroconf cluster is empty"};

			return address;
#else
			(void)arch;
			(void)sticky_source;
#endif // HAVE_AVAHI
		} else if constexpr (std::is_same_v<T, std::monostate>) {
			return nullptr;
		} else {
			static_assert(always_false_v<T>);
		}
        }, proxy_to);
}

void
Listener::OnAccept(UniqueSocketDescriptor connection_fd,
		   SocketAddress peer_address) noexcept
{
	++instance.counters.n_accepted_connections;

	PerClientAccounting *const per_client = client_accounting
		? client_accounting->Get(peer_address)
		: nullptr;
	if (per_client != nullptr) {
		per_client->UpdateTokenBucket(1);

		if (!per_client->Check()) {
			/* too many connections from this IP address -
			   reject the new connection */
			++instance.counters.n_rejected_connections;
			logger.Fmt(1, "Too many connections from {}", peer_address);
			SendEarlyDisconnect(connection_fd,
					    SSH::DisconnectReasonCode::TOO_MANY_CONNECTIONS,
					    "Too many connections"sv);
			return;
		}

		if (const auto delay = per_client->GetDelay(); delay.count() > 0) {
			++instance.counters.n_tarpit;
			logger.Fmt(1, "Connect from {} tarpit {}s", peer_address, ToFloatSeconds(delay));
			auto *c = new DelayedConnection(instance, *this,
							*per_client, delay,
							std::move(connection_fd), peer_address);
			delayed_connections.push_back(*c);
			return;
		}
	}

	try {
		auto *c = new Connection(instance, *this,
					 per_client,
					 std::move(connection_fd), peer_address);
		connections.push_front(*c);
	} catch (...) {
		logger(1, std::current_exception());
	}
}

void
Listener::OnAcceptError(std::exception_ptr ep) noexcept
{
	logger(1, "TCP accept error: ", ep);
}

#ifdef ENABLE_TRANSLATION

void
Listener::TerminateChildren(std::string_view child_tag) noexcept
{
	connections.remove_and_dispose_if([child_tag](const Connection &c){
		return c.HasTag(child_tag);
	}, [](Connection *c){
		c->Terminate();
	});
}

#endif
