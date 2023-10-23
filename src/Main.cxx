// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Instance.hxx"
#include "Config.hxx"
#include "DebugMode.hxx"
#include "key/Ed25519Key.hxx"
#include "spawn/Launch.hxx"
#include "lib/avahi/Service.hxx"
#include "lib/cap/Glue.hxx"
#include "lib/cap/State.hxx"
#include "system/ProcessName.hxx"
#include "system/SetupProcess.hxx"
#include "net/SocketConfig.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "net/IPv6Address.hxx"
#include "util/PrintException.hxx"
#include "config.h"

#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif

#ifdef HAVE_OPENSSL
#include "key/ECDSAKey.hxx"
#endif // HAVE_OPENSSL

#include <stdlib.h>

static std::unique_ptr<Key>
LoadHostKey(bool use_ed25519_host_key)
{
	if (use_ed25519_host_key) {
		auto key = std::make_unique<Ed25519Key>();
		key->Generate();
		return key;
	} else {
#ifdef HAVE_OPENSSL
		auto key = std::make_unique<ECDSAKey>();
		key->Generate();
		return key;
#else
		// TODO
		std::terminate();
#endif // HAVE_OPENSSL
	}
}

int
main(int argc, char **argv) noexcept
try {
	InitProcessName(argc, argv);

#ifndef NDEBUG
	/* also checking $SYSTEMD_EXEC_PID to see if we were launched
	   by systemd, because if we are running in a container, it
	   may not have CAP_SYS_ADMIN */
	debug_mode = !IsSysAdmin() && getenv("SYSTEMD_EXEC_PID") == nullptr;
#endif

	Config config;
	LoadConfigFile(config, "/etc/cm4all/lukko/lukko.conf");
	config.Check();

	const bool use_ed25519_host_key = true;

	SetupProcess();

	auto spawner_socket = LaunchSpawnServer(config.spawn, nullptr);

	Instance instance{
		config,
		LoadHostKey(use_ed25519_host_key),
		std::move(spawner_socket),
	};

	for (const auto &i : config.listeners)
		instance.AddListener(i);

	/* drop all capabilities, we don't need them anymore */
	CapabilityState::Empty().Install();

#ifdef HAVE_AVAHI
	instance.EnableZeroconf();
#endif // HAVE_AVAHI

#ifdef HAVE_LIBSYSTEMD
	/* tell systemd we're ready */
	sd_notify(0, "READY=1");
#endif

	/* main loop */
	instance.Run();

	return EXIT_SUCCESS;
} catch (...) {
	PrintException(std::current_exception());
	return EXIT_FAILURE;
}
