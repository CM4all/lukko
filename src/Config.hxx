// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "spawn/Config.hxx"
#include "net/AllocatedSocketAddress.hxx"
#include "net/SocketConfig.hxx"
#include "config.h"

#ifdef HAVE_AVAHI
#include "lib/avahi/ExplorerConfig.hxx"
#include "lib/avahi/ServiceConfig.hxx"
#include <map>
#endif // HAVE_AVAHI

#include <cstddef>
#include <forward_list>
#include <string>
#include <variant>

#ifdef HAVE_AVAHI

struct ZeroconfClusterConfig {
	Avahi::ServiceExplorerConfig zeroconf;

	void Check() const;
};

#endif // HAVE_AVAHI

struct ListenerConfig : SocketConfig {
#ifdef HAVE_AVAHI
	Avahi::ServiceConfig zeroconf;
#endif

#ifdef ENABLE_TRANSLATION
	std::string tag;
#endif

	std::variant<std::monostate,
#ifdef HAVE_AVAHI
		     const ZeroconfClusterConfig *,
#endif // HAVE_AVAHI
		     AllocatedSocketAddress> proxy_to;

#ifdef HAVE_AVAHI
	const ZeroconfClusterConfig *proxy_to_zeroconf_cluster = nullptr;
#endif

#ifdef ENABLE_POND
	AllocatedSocketAddress pond_server;
#endif

	std::size_t max_connections_per_ip = 0;

	bool tarpit = false;

	bool verbose_errors = false;

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

#ifdef HAVE_AVAHI
	std::map<std::string, ZeroconfClusterConfig, std::less<>> zeroconf_clusters;
#endif

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
