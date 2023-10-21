// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Instance.hxx"
#include "key/Ed25519Key.hxx"
#include "lib/avahi/Service.hxx"
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
main(int, char **) noexcept
try {
	const bool use_ed25519_host_key = true;

	SetupProcess();

	Instance instance{
		LoadHostKey(use_ed25519_host_key),
	};

	{
		SocketConfig config{IPv6Address{2200}};
		config.listen = 256;
		config.tcp_user_timeout = 60000;
		config.tcp_no_delay = true;
		config.keepalive = true;
		instance.AddListener(config.Create(SOCK_STREAM));
	}

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
