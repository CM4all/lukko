// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Instance.hxx"
#include "Listener.hxx"
#include "Connection.hxx"
#include "key/Key.hxx"
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

#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>

Instance::Instance(std::unique_ptr<Key> _host_key)
	:host_key(std::move(_host_key))
{
	shutdown_listener.Enable();
	sighup_event.Enable();
}

Instance::~Instance() noexcept = default;

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
Instance::AddListener(UniqueSocketDescriptor s)
{
	listeners.emplace_front(*this, std::move(s));

#ifdef HAVE_AVAHI
	// TODO
#endif // HAVE_AVAHI
}

void
Instance::AddConnection(UniqueSocketDescriptor fd) noexcept
{
	try {
		auto *c = new Connection(*this, std::move(fd), *host_key);
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
