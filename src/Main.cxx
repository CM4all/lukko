// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Instance.hxx"
#include "Config.hxx"
#include "DebugMode.hxx"
#include "key/Ed25519Key.hxx"
#include "key/LoadFile.hxx"
#include "key/TextFile.hxx"
#include "spawn/Launch.hxx"
#include "lib/avahi/Service.hxx"
#include "lib/cap/Glue.hxx"
#include "lib/cap/State.hxx"
#include "system/Error.hxx"
#include "system/ProcessName.hxx"
#include "system/SetupProcess.hxx"
#include "net/SocketConfig.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "net/IPv6Address.hxx"
#include "io/UniqueFileDescriptor.hxx"
#include "util/PrintException.hxx"
#include "config.h"

#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif

#ifdef HAVE_OPENSSL
#include "key/ECDSAKey.hxx"
#include "key/RSAKey.hxx"
#endif // HAVE_OPENSSL

#include <stdlib.h>

static std::unique_ptr<SecretKey>
LoadOptionalKeyFile(const char *path)
{
	UniqueFileDescriptor fd;
	if (!fd.OpenReadOnly(path)) {
		if (const int e = errno; e != ENOENT)
			throw MakeErrno("Failed to open file");

		return {};
	}

	return LoadKeyFile(fd);
}

static SecretKeyList
LoadHostKeys()
{
	SecretKeyList keys;

	if (auto key = LoadOptionalKeyFile("/etc/cm4all/lukko/host_ed25519_key"))
		keys.Add(std::move(key));

	if (auto key = LoadOptionalKeyFile("/etc/cm4all/lukko/host_ecdsa_key"))
		keys.Add(std::move(key));

	if (auto key = LoadOptionalKeyFile("/etc/cm4all/lukko/host_rsa_key"))
		keys.Add(std::move(key));

	if (keys.empty()) {
		keys.Add(std::make_unique<Ed25519Key>(Ed25519Key::Generate{}));
#ifdef HAVE_OPENSSL
		keys.Add(std::make_unique<ECDSAKey>(ECDSAKey::Generate{}));
		keys.Add(std::make_unique<RSAKey>(RSAKey::Generate{}));
#endif // HAVE_OPENSSL
	}

	return keys;
}

static PublicKeySet
LoadGlobalAuthorizedKeys()
{
	PublicKeySet keys;

	UniqueFileDescriptor fd;
	if (fd.OpenReadOnly("/etc/cm4all/lukko/authorized_keys"))
		LoadPublicKeysTextFile(keys, fd);

	return keys;
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

	SetupProcess();

	auto spawner_socket = LaunchSpawnServer(config.spawn, nullptr);

	Instance instance{
		config,
		LoadHostKeys(),
		LoadGlobalAuthorizedKeys(),
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
