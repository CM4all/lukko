// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Instance.hxx"
#include "Config.hxx"
#include "Listener.hxx"
#include "key/Key.hxx"
#include "spawn/Client.hxx"
#include "thread/Pool.hxx"
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

#include <cassert>

#include <signal.h>
#include <unistd.h>

Instance::Instance(const Config &config,
		   SecretKeyList &&_host_keys,
		   PublicKeySet &&_global_authorized_keys,
		   PublicKeySet &&_authorized_host_keys,
		   UniqueSocketDescriptor spawner_socket)
	:host_keys(std::move(_host_keys)),
	 global_authorized_keys(std::move(_global_authorized_keys)),
	 authorized_host_keys(std::move(_authorized_host_keys)),
#ifdef ENABLE_TRANSLATION
	 translation_server(config.translation_server.empty() ? nullptr : config.translation_server.c_str()),
#endif
	 spawn_service(new SpawnServerClient(event_loop,
					     config.spawn,
					     std::move(spawner_socket)))
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
		const auto local_address = listener.GetSocket().GetLocalAddress();
		if (local_address.IsDefined()) {
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
