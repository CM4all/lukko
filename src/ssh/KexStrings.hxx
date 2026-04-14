// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "KexEnums.hxx"
#include "StringList.hxx"
#include "util/IterableSplitString.hxx"

namespace SSH {

static constexpr std::string_view
FindCommonAlgorithm(std::string_view preferred, std::string_view supported) noexcept
{
	for (const std::string_view i : IterableSplitString(preferred, ','))
		if (StringListContains(supported, i))
			return i;

	return {};
}

static constexpr std::string_view
GetPeerAlgorithms(Role role, Direction direction,
		  std::string_view peer_algorithms_client_to_server,
		  std::string_view peer_algorithms_server_to_client) noexcept
{
	switch (direction) {
	case Direction::INCOMING:
		return role == Role::SERVER
			? peer_algorithms_client_to_server
			: peer_algorithms_server_to_client;

	case Direction::OUTGOING:
		return role == Role::SERVER
			? peer_algorithms_server_to_client
			: peer_algorithms_client_to_server;
	}

	std::unreachable();
}

static constexpr std::string_view
FindNegotiatedAlgorithm(Role role, Direction direction,
			std::string_view local_algorithms,
			std::string_view peer_algorithms_client_to_server,
			std::string_view peer_algorithms_server_to_client) noexcept
{
	const auto peer_algorithms = GetPeerAlgorithms(role, direction,
						       peer_algorithms_client_to_server,
						       peer_algorithms_server_to_client);

	return role == Role::SERVER
		? FindCommonAlgorithm(peer_algorithms, local_algorithms)
		: FindCommonAlgorithm(local_algorithms, peer_algorithms);
}

} // namespace SSH
