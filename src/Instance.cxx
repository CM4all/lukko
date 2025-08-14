// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "Instance.hxx"
#include "Config.hxx"
#include "Listener.hxx"
#include "key/Key.hxx"
#include "spawn/Client.hxx"
#include "thread/Pool.hxx"
#include "event/net/PrometheusExporterListener.hxx"
#include "net/SocketConfig.hxx"
#include "net/StaticSocketAddress.hxx"
#include "util/ByteOrder.hxx"

#ifdef ENABLE_CONTROL
#include "event/net/control/Server.hxx"
#endif

#ifdef HAVE_AVAHI
#include "lib/avahi/Client.hxx"
#include "lib/avahi/Publisher.hxx"
#include "lib/avahi/Service.hxx"
#endif

#include <fmt/core.h>

#include <cassert>

#include <signal.h>
#include <unistd.h>

Instance::Instance(const Config &config,
		   SecretKeyList &&_host_keys,
		   PublicKeySet &&_global_authorized_keys,
		   PublicKeySet &&_authorized_host_keys,
		   UniqueSocketDescriptor spawner_socket,
		   bool cgroup)
	:host_keys(std::move(_host_keys)),
	 global_authorized_keys(std::move(_global_authorized_keys)),
	 authorized_host_keys(std::move(_authorized_host_keys)),
#ifdef ENABLE_TRANSLATION
	 translation_server(config.translation_server.empty() ? nullptr : config.translation_server.c_str()),
#endif
	 spawn_service(new SpawnServerClient(event_loop,
					     config.spawn,
					     std::move(spawner_socket),
					     cgroup))
{
	shutdown_listener.Enable();
	sighup_event.Enable();

#ifdef ENABLE_CONTROL
	for (const auto &i : config.control_listeners) {
		BengControl::Handler &handler = *this;
		control_listeners.emplace_front(event_loop,
						i.Create(SOCK_DGRAM),
						handler);
	}
#endif

	for (const auto &i : config.prometheus_exporters) {
		PrometheusExporterHandler &handler = *this;
		prometheus_exporters.emplace_front(event_loop,
						   i.Create(SOCK_STREAM),
						   handler);
	}
}

Instance::~Instance() noexcept = default;

SpawnService &
Instance::GetSpawnService() const noexcept
{
	return *spawn_service;
}

#ifdef HAVE_AVAHI

Avahi::Client &
Instance::GetAvahiClient()
{
	if (!avahi_client) {
		Avahi::ErrorHandler &error_handler = *this;
		avahi_client = std::make_unique<Avahi::Client>(event_loop,
							       error_handler);
	}

	return *avahi_client;
}

void
Instance::EnableZeroconf() noexcept
{
	assert(!avahi_publisher);

	if (avahi_services.empty())
		return;

	Avahi::ErrorHandler &error_handler = *this;
	avahi_publisher = std::make_unique<Avahi::Publisher>(GetAvahiClient(),
							     "Lukko",
							     error_handler);

	for (auto &i : avahi_services)
		avahi_publisher->AddService(i);
}

void
Instance::DisableZeroconf() noexcept
{
	if (!avahi_publisher)
		return;

	for (auto &i : avahi_services)
		avahi_publisher->RemoveService(i);

	avahi_publisher.reset();
}

#endif // HAVE_AVAHI

void
Instance::AddListener(const ListenerConfig &config)
{
	listeners.emplace_front(*this, config);

#ifdef HAVE_AVAHI
	auto &listener = listeners.front();

	if (!config.zeroconf_service.empty()) {
		/* ask the kernel for the effective address via
		   getsockname(), because it may have changed, e.g. if
		   the kernel has selected a port for us */
		if (const auto local_address = listener.GetSocket().GetLocalAddress();
		    local_address.IsDefined()) {
			const char *const interface = config.interface.empty()
				? nullptr
				: config.interface.c_str();

			avahi_services.emplace_front(config.zeroconf_service.c_str(),
						     interface, local_address,
						     config.v6only);
		}
	}
#endif // HAVE_AVAHI
}

void
Instance::OnExit() noexcept
{
	if (should_exit)
		return;

	should_exit = true;

	shutdown_listener.Disable();
	sighup_event.Disable();

	thread_pool_stop();

	spawn_service->Shutdown();

#ifdef ENABLE_CONTROL
	control_listeners.clear();
#endif

#ifdef HAVE_AVAHI
	DisableZeroconf();
	avahi_client.reset();
#endif // HAVE_AVAHI

	listeners.clear();
	prometheus_exporters.clear();

	thread_pool_join();
}

void
Instance::OnReload(int) noexcept
{
}

#ifdef HAVE_AVAHI

bool
Instance::OnAvahiError(std::exception_ptr e) noexcept
{
	logger(1, e);
	return true;
}

#endif // HAVE_AVAHI

std::string
Instance::OnPrometheusExporterRequest()
{
	Listener::Stats listener_stats;
	for (const auto &i : listeners)
		listener_stats += i.GetStats();

	const auto &spawn_stats = spawn_service->GetStats();

	return fmt::format(R"(
# HELP lukko_children_spawned Total number of child processes spawned
# TYPE lukko_children_spawned counter

# HELP lukko_spawn_errors Total number of child processes that failed to spawn
# TYPE lukko_spawn_errors counter

# HELP lukko_children_killed Total number of child processes that were killed with a signal
# TYPE lukko_children_killed counter

# HELP lukko_children_exited Total number of child processes that have exited
# TYPE lukko_children_exited counter

# HELP lukko_children Number of child processes
# TYPE lukko_children gauge

# HELP lukko_connections_accepted Number of accepted SSH connections (including those that were rejected later)
# TYPE lukko_connections_accepted counter

# HELP lukko_connections_rejected Number of rejected SSH connections
# TYPE lukko_connections_rejected counter

# HELP lukko_connections_closed Number of times a SSH connection was closed
# TYPE lukko_connections_closed counter

# HELP lukko_userauth_received Number of userauth requests that were received
# TYPE lukko_userauth_received counter

# HELP lukko_userauth_accepted Number of userauth requests that were accepted
# TYPE lukko_userauth_accepted counter

# HELP lukko_userauth_failed Number of userauth requests that have failed
# TYPE lukko_userauth_failed counter

# HELP lukko_translation_errors Number of translation server failures
# TYPE lukko_translation_errors counter

# HELP lukko_tarpit Number of times a tarpit delay was applied
# TYPE lukko_tarpit counter

# HELP lukko_bytes_received Number of bytes sent
# TYPE lukko_bytes_received counter
# HELP lukko_bytes_sent Number of bytes sent
# TYPE lukko_bytes_sent counter

# HELP lukko_packets_received Number of packets sent
# TYPE lukko_packets_received counter
# HELP lukko_packets_sent Number of packets sent
# TYPE lukko_packets_sent counter

# HELP lukko_connections_active Number of active SSH connections
# TYPE lukko_connections_active gauge

lukko_children_spawned {}
lukko_spawn_errors {}
lukko_children_killed {}
lukko_children_exited {}
lukko_children {}

lukko_connections_accepted {}
lukko_connections_rejected {}
lukko_connections_closed{{reason="terminated"}} {}
lukko_connections_closed{{reason="unsupported_service"}} {}
lukko_connections_closed{{reason="protocol"}} {}
lukko_userauth_received {}
lukko_userauth_accepted{{method="password"}} {}
lukko_userauth_accepted{{method="publickey"}} {}
lukko_userauth_accepted{{method="hostbased"}} {}
lukko_userauth_failed{{method="password"}} {}
lukko_userauth_failed{{method="publickey"}} {}
lukko_userauth_failed{{method="hostbased"}} {}
lukko_userauth_failed{{method="unsupported"}} {}
lukko_userauth_failed{{method="unknown"}} {}
lukko_translation_errors {}
lukko_tarpit {}
lukko_bytes_received {}
lukko_bytes_sent {}
lukko_packets_received {}
lukko_packets_sent {}
lukko_connections_active {}
)",
			   spawn_stats.spawned,
			   spawn_stats.errors,
			   spawn_stats.killed,
			   spawn_stats.exited,
			   spawn_stats.alive,

			   counters.n_accepted_connections,
			   counters.n_rejected_connections,
			   counters.n_terminated_connections,
			   counters.n_unsupported_service,
			   counters.n_protocol_errors,
			   counters.n_userauth_received,
			   counters.n_userauth_password_accepted,
			   counters.n_userauth_publickey_accepted,
			   counters.n_userauth_hostbased_accepted,
			   counters.n_userauth_password_failed,
			   counters.n_userauth_publickey_failed,
			   counters.n_userauth_hostbased_failed,
			   counters.n_userauth_unsupported_failed,
			   counters.n_userauth_unknown_failed,
			   counters.n_translation_errors,
			   counters.n_tarpit,
			   ssh_metrics.bytes_received,
			   ssh_metrics.bytes_sent,
			   ssh_metrics.packets_received,
			   ssh_metrics.packets_sent,
			   listener_stats.n_connections);
}

void
Instance::OnPrometheusExporterError(std::exception_ptr error) noexcept
{
	logger(1, error);
}
