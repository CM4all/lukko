// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "event/Loop.hxx"
#include "event/ShutdownListener.hxx"
#include "event/SignalEvent.hxx"
#include "io/Logger.hxx"
#include "util/IntrusiveList.hxx"
#include "config.h"

#ifdef HAVE_AVAHI
#include "lib/avahi/ErrorHandler.hxx"
#endif

#include <forward_list>
#include <memory>

#include <stdint.h>

struct ListenerConfig;
class Key;
class UniqueSocketDescriptor;
class Listener;
class Connection;
namespace Avahi { class Client; class Publisher; struct Service; }

class Instance final
#ifdef HAVE_AVAHI
	:Avahi::ErrorHandler
#endif
{
	static constexpr size_t MAX_DATAGRAM_SIZE = 4096;

	const RootLogger logger;

	std::unique_ptr<Key> host_key;

	EventLoop event_loop;

	bool should_exit = false;

	ShutdownListener shutdown_listener{event_loop, BIND_THIS_METHOD(OnExit)};
	SignalEvent sighup_event{event_loop, SIGHUP, BIND_THIS_METHOD(OnReload)};

#ifdef HAVE_AVAHI
	std::unique_ptr<Avahi::Client> avahi_client;
	std::forward_list<Avahi::Service> avahi_services;
	std::unique_ptr<Avahi::Publisher> avahi_publisher;
#endif // HAVE_AVAHI

	std::forward_list<Listener> listeners;

	IntrusiveList<Connection> connections;

public:
	explicit Instance(std::unique_ptr<Key> _host_key);
	~Instance() noexcept;

	const RootLogger &GetLogger() const noexcept {
		return logger;
	}

	auto &GetEventLoop() noexcept {
		return event_loop;
	}

#ifdef HAVE_AVAHI
	Avahi::Client &GetAvahiClient();

	void EnableZeroconf() noexcept;
	void DisableZeroconf() noexcept;
#endif // HAVE_AVAHI

	void AddListener(const ListenerConfig &config);
	void AddConnection(UniqueSocketDescriptor s) noexcept;

	void Run() noexcept {
		event_loop.Run();
	}

private:
	void OnExit() noexcept;
	void OnReload(int) noexcept;

#ifdef HAVE_AVAHI
	/* virtual methods from class Avahi::ErrorHandler */
	bool OnAvahiError(std::exception_ptr e) noexcept override;
#endif // HAVE_AVAHI
};
