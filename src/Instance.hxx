// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "ssh/Metrics.hxx"
#include "key/List.hxx"
#include "key/Set.hxx"
#include "event/Loop.hxx"
#include "event/ShutdownListener.hxx"
#include "event/SignalEvent.hxx"
#include "event/net/PrometheusExporterHandler.hxx"
#include "io/Logger.hxx"
#include "config.h"

#ifdef HAVE_AVAHI
#include "lib/avahi/ErrorHandler.hxx"
#endif

#ifdef ENABLE_CONTROL
#include "event/net/control/Handler.hxx"
#endif

#include <cstdint>
#include <forward_list>
#include <memory>

struct Config;
struct ListenerConfig;
namespace BengControl { class Server; }
class SecretKey;
class UniqueSocketDescriptor;
class Listener;
class PrometheusExporterListener;
class SpawnService;
class SpawnServerClient;

#ifdef HAVE_AVAHI
#include <map>
struct ZeroconfClusterConfig;
class ZeroconfCluster;
namespace Avahi { class Client; class Publisher; struct Service; }
#endif // HAVE_AVAHI

struct DummyBase {};

class Instance final
	:DummyBase,
#ifdef ENABLE_CONTROL
	 BengControl::Handler,
#endif
#ifdef HAVE_AVAHI
	 Avahi::ErrorHandler,
#endif
	 PrometheusExporterHandler
{
	static constexpr size_t MAX_DATAGRAM_SIZE = 4096;

	const RootLogger logger;

	const SecretKeyList host_keys;

	const PublicKeySet global_authorized_keys;

#ifdef ENABLE_TRANSLATION
	const char *const translation_server;
#endif

	EventLoop event_loop;

	bool should_exit = false;

	ShutdownListener shutdown_listener{event_loop, BIND_THIS_METHOD(OnExit)};
	SignalEvent sighup_event{event_loop, SIGHUP, BIND_THIS_METHOD(OnReload)};

#ifdef ENABLE_CONTROL
	std::forward_list<BengControl::Server> control_listeners;
#endif

#ifdef HAVE_AVAHI
	std::unique_ptr<Avahi::Client> avahi_client;
	std::forward_list<Avahi::Service> avahi_services;
	std::unique_ptr<Avahi::Publisher> avahi_publisher;

	std::map<const ZeroconfClusterConfig *, ZeroconfCluster> zeroconf_clusters;
#endif // HAVE_AVAHI

	std::forward_list<Listener> listeners;

	std::forward_list<PrometheusExporterListener> prometheus_exporters;

	std::unique_ptr<SpawnServerClient> spawn_service;

public:
	Instance(const Config &config,
		 SecretKeyList &&_host_key,
		 PublicKeySet &&_global_authorized_keys,
		 UniqueSocketDescriptor spawner_socket,
		 bool cgroups);
	~Instance() noexcept;

	const RootLogger &GetLogger() const noexcept {
		return logger;
	}

	const auto &GetHostKeys() const noexcept {
		return host_keys;
	}

	const auto &GetGlobalAuthorizedKeys() const noexcept {
		return global_authorized_keys;
	}

	auto &GetEventLoop() noexcept {
		return event_loop;
	}

#ifdef ENABLE_TRANSLATION
	const char *GetTranslationServer() const noexcept {
		return translation_server;
	}
#endif

	[[gnu::const]]
	SpawnService &GetSpawnService() const noexcept;

#ifdef HAVE_AVAHI
	Avahi::Client &GetAvahiClient();

	/**
	 * Create a #ZeroconfCluster instance from a
	 * #ZeroconfClusterConfig, possibly returning an instance that
	 * is shared between multiple callers.  The returned object is
	 * owned by this #Instance.  Supposed to be called during
	 * startup.
	 *
	 * Throws on error.
	 */
	ZeroconfCluster &MakeZeroconfCluster(const ZeroconfClusterConfig &config);

	void EnableZeroconf() noexcept;
	void DisableZeroconf() noexcept;
#endif // HAVE_AVAHI

	void AddListener(const ListenerConfig &config);

	void Run() noexcept {
		event_loop.Run();
	}

	struct Counters {
		uint_least64_t n_accepted_connections = 0;
		uint_least64_t n_rejected_connections = 0;
		uint_least64_t n_tarpit = 0;
		uint_least64_t n_terminated_connections = 0;
		uint_least64_t n_unsupported_service = 0;
		uint_least64_t n_userauth_received = 0;
		uint_least64_t n_userauth_unsupported = 0;
		uint_least64_t n_protocol_errors = 0;
		uint_least64_t n_userauth_password_accepted = 0;
		uint_least64_t n_userauth_publickey_accepted = 0;
		uint_least64_t n_userauth_hostbased_accepted = 0;
		uint_least64_t n_userauth_password_failed = 0;
		uint_least64_t n_userauth_publickey_failed = 0;
		uint_least64_t n_userauth_hostbased_failed = 0;
		uint_least64_t n_userauth_unsupported_failed = 0;
		uint_least64_t n_userauth_unknown_failed = 0;
		uint_least64_t n_userauth_timeouts = 0;
		uint_least64_t n_translation_errors = 0;
	} counters;

	SSH::Metrics ssh_metrics{};

private:
	void OnExit() noexcept;
	void OnReload(int) noexcept;

#ifdef ENABLE_CONTROL
	/* virtual methods from class ControlHandler */
	void OnControlPacket(BengControl::Command command,
			     std::span<const std::byte> payload,
			     std::span<UniqueFileDescriptor> fds,
			     SocketAddress address, int uid) override;

	void OnControlError(std::exception_ptr ep) noexcept override;
#endif // ENABLE_CONTROL

#ifdef HAVE_AVAHI
	/* virtual methods from class Avahi::ErrorHandler */
	bool OnAvahiError(std::exception_ptr e) noexcept override;
#endif // HAVE_AVAHI

	/* virtual methods from class PrometheusExporterHandler */
	std::string OnPrometheusExporterRequest() override;
	void OnPrometheusExporterError(std::exception_ptr error) noexcept override;
};
