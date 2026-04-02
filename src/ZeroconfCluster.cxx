// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "ZeroconfCluster.hxx"
#include "lib/avahi/Explorer.hxx"
#include "lib/avahi/ExplorerConfig.hxx"
#include "net/rh/Node.hxx"

#include <algorithm> // for std::sort()

using std::string_view_literals::operator""sv;

struct ZeroconfCluster::Member final : RendezvousHashing::Node {};

ZeroconfCluster::ZeroconfCluster(Avahi::Client &client,
				 Avahi::ErrorHandler &error_handler,
				 const Avahi::ServiceExplorerConfig &config)
	:explorer(config.Create(client, *this, error_handler))
{
}

ZeroconfCluster::~ZeroconfCluster() noexcept = default;

inline void
ZeroconfCluster::FillMemberList() noexcept
{
	member_list.clear();
	member_list.reserve(member_map.size());

	for (auto i = member_map.begin(); i != member_map.end(); ++i)
		member_list.push_back(i);
}

SocketAddress
ZeroconfCluster::Pick(Arch arch, std::span<const std::byte> sticky_source) noexcept
{
	if (dirty) {
		dirty = false;
		FillMemberList();
	}

	if (member_list.empty())
		return nullptr;

	for (auto &i : member_list)
		i->second.UpdateRendezvousScore(sticky_source);

	/* sort the all members by a mix of its address hash and the
	   request's hash */
	std::sort(member_list.begin(), member_list.end(),
		  [arch](MemberMap::const_iterator a,
			 MemberMap::const_iterator b) noexcept {
			  return RendezvousHashing::Node::Compare(arch, a->second, b->second);
		  });

	return member_list.front()->second.GetAddress();
}

void
ZeroconfCluster::OnAvahiNewObject(const std::string &key,
				  [[maybe_unused]] const char *host_name,
				  const InetAddress &address,
				  AvahiStringList *txt,
				  Avahi::ObjectFlags flags) noexcept
{
	auto [it, inserted] = member_map.try_emplace(key);
	it->second.Update(address, txt, flags);

	dirty = true;
}

void
ZeroconfCluster::OnAvahiRemoveObject(const std::string &key) noexcept
{
	auto i = member_map.find(key);
	if (i == member_map.end())
		return;

	/* TODO: purge entry from the "failure" map, because it
	   will never be used again anyway */

	member_map.erase(i);
	dirty = true;
}
