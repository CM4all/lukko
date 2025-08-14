// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "KexProposal.hxx"
#include "Serializer.hxx"

namespace SSH {

void
SerializeProposal(Serializer &s, const KexProposal &proposal)
{
	s.WriteString(proposal.kex_algorithms);
	s.WriteString(proposal.server_host_key_algorithms);
	s.WriteString(proposal.encryption_algorithms_client_to_server);
	s.WriteString(proposal.encryption_algorithms_server_to_client);
	s.WriteString(proposal.mac_algorithms_client_to_server);
	s.WriteString(proposal.mac_algorithms_server_to_client);
	s.WriteString(proposal.compression_algorithms_client_to_server);
	s.WriteString(proposal.compression_algorithms_server_to_client);
	s.WriteString(proposal.languages_client_to_server);
	s.WriteString(proposal.languages_server_to_client);
}

} // namespace SSH
