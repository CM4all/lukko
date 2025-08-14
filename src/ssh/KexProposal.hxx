// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <string_view>

namespace SSH {

class Serializer;

struct KexProposal {
	std::string_view kex_algorithms;
	std::string_view server_host_key_algorithms;
	std::string_view encryption_algorithms_client_to_server;
	std::string_view encryption_algorithms_server_to_client;
	std::string_view mac_algorithms_client_to_server;
	std::string_view mac_algorithms_server_to_client;
	std::string_view compression_algorithms_client_to_server;
	std::string_view compression_algorithms_server_to_client;
	std::string_view languages_client_to_server;
	std::string_view languages_server_to_client;
};

void
SerializeProposal(Serializer &s, const KexProposal &proposal);

} // namespace SSH
