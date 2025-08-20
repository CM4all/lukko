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
OutgoingConnection::Destroy() noexcept
{
	handler.OnOutgoingDestroy();
}

void
OutgoingConnection::SendUserauthRequestHostbased(std::string_view username,
						 const SecretKey &key,
						 std::string_view key_algorithm)
{
	assert(state == State::SERVICE_SSH_USERAUTH);

	// TODO
	const std::string_view client_host_name = "localhost"sv;
	const std::string_view client_user_name = "dummy"sv;

	SSH::PacketSerializer s{SSH::MessageNumber::USERAUTH_REQUEST};
	const auto to_be_signed_marker = s.Mark();
	s.WriteString(username);
	s.WriteString("ssh-connection"sv);
	s.WriteString("hostbased"sv);
	s.WriteString(key_algorithm);

	const auto key_length = s.PrepareLength();
	key.SerializePublic(s);
	s.CommitLength(key_length);

	s.WriteString(client_host_name);
	s.WriteString(client_user_name);

	const auto to_be_signed = s.Since(to_be_signed_marker);

	SSH::Serializer s2;
	s2.WriteLengthEncoded(GetSessionId());
	s2.WriteU8(static_cast<uint_least8_t>(SSH::MessageNumber::USERAUTH_REQUEST));
	s2.WriteN(to_be_signed);

	const auto signature_length = s.PrepareLength();
	key.Sign(s, s2.Finish(), key_algorithm);
	s.CommitLength(signature_length);

	SendPacket(std::move(s));

	state = State::USERAUTH_REQUEST;
}

inline void
OutgoingConnection::HandleServiceAccept(std::span<const std::byte> payload)
{
	const auto p = SSH::ParseServiceAccept(payload);

	if (state == State::SERVICE_REQUEST_SSH_USERAUTH &&
	    p.service_name == "ssh-userauth"sv) {
		state = State::SERVICE_SSH_USERAUTH;

		handler.OnOutgoingUserauthService();
	} else
		throw Disconnect{
			SSH::DisconnectReasonCode::PROTOCOL_ERROR,
			"Unexpected SERVICE_ACCEPT"sv,
		};
}

void
OutgoingConnection::HandlePacket(SSH::MessageNumber msg,
				 std::span<const std::byte> payload)
{
	if (!IsEncrypted())
		return Connection::HandlePacket(msg, payload);

	switch (msg) {
	case SSH::MessageNumber::SERVICE_ACCEPT:
		HandleServiceAccept(payload);
		break;

	case SSH::MessageNumber::USERAUTH_FAILURE:
		if (state == State::USERAUTH_REQUEST) {
			state = State::SERVICE_SSH_USERAUTH;
			handler.OnOutgoingUserauthFailure();
		} else
			throw Disconnect{
				SSH::DisconnectReasonCode::PROTOCOL_ERROR,
				"Unexpected USERAUTH_FAILURE"sv,
			};

		break;

	case SSH::MessageNumber::USERAUTH_SUCCESS:
		if (state == State::USERAUTH_REQUEST) {
			state = State::USERAUTH_SUCCESS;
			handler.OnOutgoingUserauthSuccess();
		} else
			throw Disconnect{
				SSH::DisconnectReasonCode::PROTOCOL_ERROR,
				"Unexpected USERAUTH_SUCCESS"sv,
			};

		break;

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
		if (state == State::USERAUTH_SUCCESS) {
			handler.OnOutgoingHandlePacket(msg, payload);
		} else
			throw Disconnect{
				SSH::DisconnectReasonCode::PROTOCOL_ERROR,
				"Unexpected packet"sv,
			};

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
	assert(state == State::INIT);

	SendPacket(SSH::MakeServiceRequest("ssh-userauth"sv));
	state = State::SERVICE_REQUEST_SSH_USERAUTH;
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
	PrintException(e);
	SSH::Connection::OnBufferedError(std::move(e));
}
