// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "key/List.hxx"
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

struct Config;
struct ListenerConfig;
class SecretKey;
class UniqueSocketDescriptor;
class Listener;
class Connection;
class SpawnService;
class SpawnServerClient;
namespace Avahi { class Client; class Publisher; struct Service; }

class Instance final
#ifdef HAVE_AVAHI
	:Avahi::ErrorHandler
#endif
{
	static constexpr size_t MAX_DATAGRAM_SIZE = 4096;

	const RootLogger logger;

	const SecretKeyList host_keys;

#ifdef ENABLE_TRANSLATION
	const char *const translation_server;
#endif

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

	std::unique_ptr<SpawnServerClient> spawn_service;

public:
	Instance(const Config &config,
		 SecretKeyList &&_host_key,
		 UniqueSocketDescriptor spawner_socket);
	~Instance() noexcept;

	const RootLogger &GetLogger() const noexcept {
		return logger;
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

	void EnableZeroconf() noexcept;
	void DisableZeroconf() noexcept;
#endif // HAVE_AVAHI

	void AddListener(const ListenerConfig &config);
	void AddConnection(Listener &listener, UniqueSocketDescriptor s) noexcept;

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
