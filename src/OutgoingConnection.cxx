// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "OutgoingConnection.hxx"
#include "ssh/ParsePacket.hxx"
#include "key/Key.hxx"
#include "key/Set.hxx"
#include "ssh/MakePacket.hxx"
#include "ssh/PacketSerializer.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "util/PrintException.hxx"
#include "util/StringSplit.hxx"

using std::string_view_literals::operator""sv;

OutgoingConnection::OutgoingConnection(EventLoop &event_loop,
				       const PublicKeySet &_server_host_keys,
				       UniqueSocketDescriptor &&fd,
				       OutgoingConnectionHandler &_handler)
	:SSH::Connection(event_loop, std::move(fd), SSH::Role::CLIENT),
	 server_host_keys(_server_host_keys),
	 handler(_handler) {}

OutgoingConnection::~OutgoingConnection() noexcept = default;

void
OutgoingConnection::SendUserauthRequestHostbased(std::string_view username,
						 const SecretKey &key,
						 std::string_view key_algorithm,
						 std::string_view client_host_name,
						 std::string_view client_user_name)
{
	assert(user_auth);

	user_auth->SendUserAuthRequestHostbased(username, key, key_algorithm,
						client_host_name, client_user_name);
}

void
OutgoingConnection::OnUserAuthService()
{
	assert(user_auth);

	handler.OnOutgoingUserauthService();
}

void
OutgoingConnection::OnUserAuthSuccess()
{
	assert(user_auth);
	user_auth.reset();

	SetAuthenticated();
	handler.OnOutgoingUserauthSuccess();
}

void
OutgoingConnection::OnUserAuthFailure()
{
	assert(user_auth);
	user_auth.reset();

	handler.OnOutgoingUserauthFailure();
}

void
OutgoingConnection::Destroy() noexcept
{
	handler.OnOutgoingDestroy();
}

void
OutgoingConnection::HandlePacket(SSH::MessageNumber msg,
				 std::span<const std::byte> payload)
{
	if (!IsAuthenticated())
		return Connection::HandlePacket(msg, payload);

	assert(IsEncrypted());

	switch (msg) {
	case SSH::MessageNumber::GLOBAL_REQUEST:
	case SSH::MessageNumber::REQUEST_SUCCESS:
	case SSH::MessageNumber::REQUEST_FAILURE:
	case SSH::MessageNumber::CHANNEL_OPEN:
	case SSH::MessageNumber::CHANNEL_OPEN_CONFIRMATION:
	case SSH::MessageNumber::CHANNEL_OPEN_FAILURE:
	case SSH::MessageNumber::CHANNEL_WINDOW_ADJUST:
	case SSH::MessageNumber::CHANNEL_DATA:
	case SSH::MessageNumber::CHANNEL_EXTENDED_DATA:
	case SSH::MessageNumber::CHANNEL_EOF:
	case SSH::MessageNumber::CHANNEL_CLOSE:
	case SSH::MessageNumber::CHANNEL_REQUEST:
	case SSH::MessageNumber::CHANNEL_SUCCESS:
	case SSH::MessageNumber::CHANNEL_FAILURE:
		handler.OnOutgoingHandlePacket(msg, payload);
		break;

	default:
		SSH::Connection::HandlePacket(msg, payload);
	}
}

bool
OutgoingConnection::CheckHostKey(std::span<const std::byte> server_host_key_blob) const noexcept
{
	return server_host_keys.Contains(server_host_key_blob);
}

void
OutgoingConnection::OnEncrypted()
{
	assert(!user_auth);

	SSH::UserAuthClientHandler &user_auth_handler = *this;
	user_auth = std::make_unique<SSH::UserAuthClient>(*this, user_auth_handler);
	user_auth->Start();
}

void
OutgoingConnection::OnDisconnecting(SSH::DisconnectReasonCode reason_code,
				    std::string_view msg) noexcept
{
	SSH::Connection::OnDisconnecting(reason_code, msg);

	handler.OnOutgoingDisconnecting(reason_code, msg);
}

void
OutgoingConnection::OnDisconnected(SSH::DisconnectReasonCode reason_code,
				   std::string_view msg) noexcept
{
	handler.OnOutgoingDisconnected(reason_code, msg);
}

void
OutgoingConnection::OnBufferedError(std::exception_ptr e) noexcept
{
	handler.OnOutgoingError(std::move(e));
}
