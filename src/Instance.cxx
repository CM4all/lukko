// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Instance.hxx"
#include "Config.hxx"
#include "Listener.hxx"
#include "Connection.hxx"
#include "key/Key.hxx"
#include "spawn/Client.hxx"
#include "event/net/MultiUdpListener.hxx"
#include "net/SocketConfig.hxx"
#include "net/StaticSocketAddress.hxx"
#include "util/ByteOrder.hxx"
#include "util/DeleteDisposer.hxx"
#include "util/PrintException.hxx"

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
		   UniqueSocketDescriptor spawner_socket)
	:host_keys(std::move(_host_keys)),
	 global_authorized_keys(std::move(_global_authorized_keys)),
#ifdef ENABLE_TRANSLATION
	 translation_server(config.translation_server.empty() ? nullptr : config.translation_server.c_str()),
#endif
	 spawn_service(new SpawnServerClient(event_loop,
					     config.spawn,
					     std::move(spawner_socket)))
{
	shutdown_listener.Enable();
	sighup_event.Enable();
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
							     avahi_services,
							     error_handler);
}

void
Instance::DisableZeroconf() noexcept
{
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
		const auto local_address = listener.GetLocalAddress();
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
Instance::AddConnection(Listener &listener, UniqueSocketDescriptor fd) noexcept
{
	try {
		auto *c = new Connection(*this, listener, std::move(fd), host_keys);
		connections.push_front(*c);
	} catch (...) {
		logger(1, std::current_exception());
	}
}

void
Instance::OnExit() noexcept
{
	if (should_exit)
		return;

	should_exit = true;

	shutdown_listener.Disable();
	sighup_event.Disable();

	spawn_service->Shutdown();

#ifdef HAVE_AVAHI
	avahi_publisher.reset();
	avahi_client.reset();
#endif // HAVE_AVAHI

	connections.clear_and_dispose(DeleteDisposer{});

	listeners.clear();
}

void
Instance::OnReload(int) noexcept
{
}

#ifdef HAVE_AVAHI

bool
Instance::OnAvahiError(std::exception_ptr e) noexcept
{
	PrintException(e);
	return true;
}

#endif // HAVE_AVAHI
