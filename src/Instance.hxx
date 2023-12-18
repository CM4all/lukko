// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "key/List.hxx"
#include "key/Set.hxx"
#include "event/Loop.hxx"
#include "event/ShutdownListener.hxx"
#include "event/SignalEvent.hxx"
#include "io/Logger.hxx"
#include "util/IntrusiveList.hxx"
#include "config.h"

#ifdef HAVE_AVAHI
#include "lib/avahi/ErrorHandler.hxx"
#endif

#ifdef ENABLE_CONTROL
#include "event/net/control/Handler.hxx"
#endif

#include <forward_list>
#include <memory>

#include <stdint.h>

struct Config;
struct ListenerConfig;
class ControlServer;
class SecretKey;
class UniqueSocketDescriptor;
class Listener;
class Connection;
class SpawnService;
class SpawnServerClient;
namespace Avahi { class Client; class Publisher; struct Service; }

struct DummyBase {};

class Instance final
	:DummyBase
#ifdef ENABLE_CONTROL
	, ControlHandler
#endif
#ifdef HAVE_AVAHI
	, Avahi::ErrorHandler
#endif
{
	static constexpr size_t MAX_DATAGRAM_SIZE = 4096;

	const RootLogger logger;

	const SecretKeyList host_keys;

	const PublicKeySet global_authorized_keys;

	const PublicKeySet authorized_host_keys;

#ifdef ENABLE_TRANSLATION
	const char *const translation_server;
#endif

	EventLoop event_loop;

	bool should_exit = false;

	ShutdownListener shutdown_listener{event_loop, BIND_THIS_METHOD(OnExit)};
	SignalEvent sighup_event{event_loop, SIGHUP, BIND_THIS_METHOD(OnReload)};

#ifdef ENABLE_CONTROL
	std::forward_list<ControlServer> control_listeners;
#endif

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
		 PublicKeySet &&_global_authorized_keys,
		 PublicKeySet &&_authorized_host_keys,
		 UniqueSocketDescriptor spawner_socket);
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

	const auto &GetAuthorizedHostKeys() const noexcept {
		return authorized_host_keys;
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
	void AddConnection(Listener &listener, UniqueSocketDescriptor s,
			   SocketAddress peer_address) noexcept;

	void Run() noexcept {
		event_loop.Run();
	}

private:
	void OnExit() noexcept;
	void OnReload(int) noexcept;

#ifdef ENABLE_CONTROL
	/* virtual methods from class ControlHandler */
	void OnControlPacket(ControlServer &control_server,
			     BengProxy::ControlCommand command,
			     std::span<const std::byte> payload,
			     std::span<UniqueFileDescriptor> fds,
			     SocketAddress address, int uid) override;

	void OnControlError(std::exception_ptr ep) noexcept override;
#endif // ENABLE_CONTROL

#ifdef HAVE_AVAHI
	/* virtual methods from class Avahi::ErrorHandler */
	bool OnAvahiError(std::exception_ptr e) noexcept override;
#endif // HAVE_AVAHI
};
