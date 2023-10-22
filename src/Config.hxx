// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "spawn/Config.hxx"
#include "net/SocketConfig.hxx"
#include "config.h"

#include <forward_list>

struct ListenerConfig : SocketConfig {
#ifdef HAVE_AVAHI
	std::string zeroconf_service;
#endif

	ListenerConfig() {
		listen = 256;
		tcp_no_delay = true;
	}
};

struct Config {
#ifdef ENABLE_TRANSLATION
	std::string translation_server;
#endif

	std::forward_list<ListenerConfig> listeners;

	SpawnConfig spawn;

	Config();

	void Check();
};

/**
 * Load and parse the specified configuration file.  Throws an
 * exception on error.
 */
void
LoadConfigFile(Config &config, const char *path);
