// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "lib/avahi/ExplorerListener.hxx"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

enum class Arch : uint_least8_t;
class SocketAddress;

namespace Avahi {
class Client;
class ServiceExplorer;
struct ServiceExplorerConfig;
class ErrorHandler;
}

/**
 * An instance of #ZeroconfClusterConfig, configured using the
 * "zeroconf_cluster" section.  It uses an Avahi::ServiceExplorer to
 * discover actual servers.
 */
class ZeroconfCluster final : Avahi::ServiceExplorerListener {
	std::unique_ptr<Avahi::ServiceExplorer> explorer;

	struct Member;
	using MemberMap = std::map<std::string, Member, std::less<>>;
	using MemberList = std::vector<MemberMap::iterator>;

	/**
	 * A map of name to #Member instances for discovered servers.
	 */
	MemberMap member_map;

	/**
	 * A list of #member_map iterators, to be sorted by Pick() for
	 * rendezvous hashing.
	 */
	MemberList member_list;

	bool dirty = false;

public:
	explicit ZeroconfCluster(Avahi::Client &client,
				 Avahi::ErrorHandler &error_handler,
				 const Avahi::ServiceExplorerConfig &config);
	~ZeroconfCluster() noexcept;

	/**
	 * Pick a server (using rendezvous hashing with the same hash
	 * formula as beng-lb).
	 *
	 * Returns nullptr if no server was
	 * discovered.
	 */
	[[gnu::pure]]
	SocketAddress Pick(Arch arch, std::span<const std::byte> sticky_source) noexcept;

private:
	void FillMemberList() noexcept;

	/* virtual methods from class AvahiServiceExplorerListener */
	void OnAvahiNewObject(const std::string &key,
			      const InetAddress &address,
			      AvahiStringList *txt,
			      Flags flags) noexcept override;
	void OnAvahiRemoveObject(const std::string &key) noexcept override;
};
