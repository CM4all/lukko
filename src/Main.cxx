// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Instance.hxx"
#include "CommandLine.hxx"
#include "Config.hxx"
#include "DebugMode.hxx"
#include "key/Ed25519Key.hxx"
#include "key/LoadFile.hxx"
#include "key/TextFile.hxx"
#include "memory/fb_pool.hxx"
#include "spawn/Launch.hxx"
#include "system/Error.hxx"
#include "system/ProcessName.hxx"
#include "system/SetupProcess.hxx"
#include "net/SocketConfig.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "net/IPv6Address.hxx"
#include "io/UniqueFileDescriptor.hxx"
#include "util/PrintException.hxx"
#include "config.h"

#ifdef HAVE_AVAHI
#include "lib/avahi/Service.hxx"
#endif

#ifdef HAVE_LIBCAP
#include "lib/cap/Glue.hxx"
#include "lib/cap/State.hxx"
#endif // HAVE_LIBCAP

#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif

#ifdef HAVE_OPENSSL
#include "key/ECDSAKey.hxx"
#include "key/RSAKey.hxx"
#endif // HAVE_OPENSSL

#include <filesystem>

#include <stdlib.h>

using std::string_view_literals::operator""sv;

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
LoadHostKeys(const std::filesystem::path &config_directory)
{
	SecretKeyList keys;

	static constexpr std::string_view host_key_filenames[] = {
		"host_ed25519_key"sv,
#ifdef HAVE_OPENSSL
		"host_ecdsa_key"sv,
		"host_rsa_key"sv,
#endif
	};

	for (const std::string_view filename : host_key_filenames)
		if (auto key = LoadOptionalKeyFile((config_directory / filename).c_str()))
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
LoadGlobalAuthorizedKeys(const std::filesystem::path &config_directory)
{
	PublicKeySet keys;

	UniqueFileDescriptor fd;
	if (fd.OpenReadOnly((config_directory / "authorized_keys"sv).c_str()))
		LoadPublicKeysTextFile(keys, fd);

	return keys;
}

static PublicKeySet
LoadAuthorizedHostKeys(const std::filesystem::path &config_directory)
{
	PublicKeySet keys;

	UniqueFileDescriptor fd;
	if (fd.OpenReadOnly((config_directory / "authorized_host_keys"sv).c_str()))
		LoadPublicKeysTextFile(keys, fd);

	return keys;
}

int
main(int argc, char **argv) noexcept
try {
	const auto cmdline = ParseCommandLine(argc, argv);

	InitProcessName(argc, argv);

#ifndef NDEBUG
	/* also checking $SYSTEMD_EXEC_PID to see if we were launched
	   by systemd, because if we are running in a container, it
	   may not have CAP_SYS_ADMIN */
	debug_mode =
#ifdef HAVE_LIBCAP
		!IsSysAdmin() &&
#endif
		getenv("SYSTEMD_EXEC_PID") == nullptr;
#endif

	Config config;
	LoadConfigFile(config, cmdline.config_path);
	config.Check();

	SetupProcess();

	auto spawner_socket = LaunchSpawnServer(config.spawn, nullptr);

	const ScopeFbPoolInit fb_pool_init;

	Instance instance{
		config,
		LoadHostKeys(std::filesystem::path{cmdline.config_path}.parent_path()),
		LoadGlobalAuthorizedKeys(std::filesystem::path{cmdline.config_path}.parent_path()),
		LoadAuthorizedHostKeys(std::filesystem::path{cmdline.config_path}.parent_path()),
		std::move(spawner_socket),
	};

	for (const auto &i : config.listeners)
		instance.AddListener(i);

#ifdef HAVE_LIBCAP
	/* drop all capabilities, we don't need them anymore */
	CapabilityState::Empty().Install();
#endif // HAVE_LIBCAP

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
