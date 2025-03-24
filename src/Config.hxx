// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "spawn/Config.hxx"
#include "net/AllocatedSocketAddress.hxx"
#include "net/SocketConfig.hxx"
#include "config.h"

#include <cstddef>
#include <forward_list>

struct ListenerConfig : SocketConfig {
#ifdef HAVE_AVAHI
	std::string zeroconf_service;
#endif

#ifdef ENABLE_TRANSLATION
	std::string tag;
#endif

	AllocatedSocketAddress proxy_to;

#ifdef ENABLE_POND
	AllocatedSocketAddress pond_server;
#endif

	std::size_t max_connections_per_ip = 0;

	bool tarpit = false;

	bool exec_reject_stderr = false;

	ListenerConfig() noexcept {
		listen = 256;
		tcp_no_delay = true;
	}
};

struct PrometheusExporterConfig : SocketConfig {
	PrometheusExporterConfig() noexcept {
		listen = 16;
		tcp_defer_accept = 10;
		tcp_no_delay = true;
	}
};

struct Config {
#ifdef ENABLE_TRANSLATION
	std::string translation_server;
#endif

#ifdef ENABLE_CONTROL
	struct ControlListener : SocketConfig {
		ControlListener()
			:SocketConfig{
				.pass_cred = true,
			}
		{
		}

		explicit ControlListener(SocketAddress _bind_address)
			:SocketConfig{
				.bind_address = AllocatedSocketAddress{_bind_address},
				.pass_cred = true,
			}
		{
		}
	};

	std::forward_list<ControlListener> control_listeners;
#endif // ENABLE_CONTROL

	std::forward_list<ListenerConfig> listeners;

	std::forward_list<PrometheusExporterConfig> prometheus_exporters;

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
