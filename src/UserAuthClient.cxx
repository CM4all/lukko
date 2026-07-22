// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "UserAuthClient.hxx"
#include "ssh/Connection.hxx"
#include "ssh/ParsePacket.hxx"
#include "key/Key.hxx"
#include "ssh/MakePacket.hxx"
#include "ssh/PacketSerializer.hxx"

using std::string_view_literals::operator""sv;

UserAuthClient::UserAuthClient(SSH::Connection &_connection,
			       UserAuthClientHandler &_handler)
	:connection(_connection),
	 handler(_handler)
{
	connection.AddHandler(*this);
}

UserAuthClient::~UserAuthClient() noexcept = default;

void
UserAuthClient::Start()
{
	assert(state == State::INIT);
	assert(connection.IsEncrypted());

	connection.SendPacket(SSH::MakeServiceRequest("ssh-userauth"sv));
	state = State::SERVICE_REQUEST_SSH_USERAUTH;
}

void
UserAuthClient::SendUserAuthRequestPublicKey(std::string_view username,
					     const SecretKey &key,
					     std::string_view key_algorithm)
{
	assert(state == State::SERVICE_SSH_USERAUTH);

	SSH::PacketSerializer s{SSH::MessageNumber::USERAUTH_REQUEST};
	const auto to_be_signed_marker = s.Mark();
	s.WriteString(username);
	s.WriteString("ssh-connection"sv);
	s.WriteString("publickey"sv);
	s.WriteBool(true); // with_signature
	s.WriteString(key_algorithm);

	const auto key_length = s.PrepareLength();
	key.SerializePublic(s);
	s.CommitLength(key_length);

	const auto to_be_signed = s.Since(to_be_signed_marker);

	SSH::Serializer s2;
	s2.WriteLengthEncoded(connection.GetSessionId());
	s2.WriteU8(static_cast<uint_least8_t>(SSH::MessageNumber::USERAUTH_REQUEST));
	s2.WriteN(to_be_signed);

	const auto signature_length = s.PrepareLength();
	key.Sign(s, s2.Finish(), key_algorithm);
	s.CommitLength(signature_length);

	connection.SendPacket(std::move(s));

	state = State::USERAUTH_REQUEST;
}

void
UserAuthClient::SendUserAuthRequestHostbased(std::string_view username,
					     const SecretKey &key,
					     std::string_view key_algorithm,
					     std::string_view client_host_name,
					     std::string_view client_user_name)
{
	assert(state == State::SERVICE_SSH_USERAUTH);

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
	s2.WriteLengthEncoded(connection.GetSessionId());
	s2.WriteU8(static_cast<uint_least8_t>(SSH::MessageNumber::USERAUTH_REQUEST));
	s2.WriteN(to_be_signed);

	const auto signature_length = s.PrepareLength();
	key.Sign(s, s2.Finish(), key_algorithm);
	s.CommitLength(signature_length);

	connection.SendPacket(std::move(s));

	state = State::USERAUTH_REQUEST;
}

inline void
UserAuthClient::HandleServiceAccept(std::span<const std::byte> payload)
{
	const auto p = SSH::ParseServiceAccept(payload);

	if (state == State::SERVICE_REQUEST_SSH_USERAUTH &&
	    p.service_name == "ssh-userauth"sv) {
		state = State::SERVICE_SSH_USERAUTH;

		handler.OnUserAuthService();
	} else
		throw SSH::Connection::Disconnect{
			SSH::DisconnectReasonCode::PROTOCOL_ERROR,
			"Unexpected SERVICE_ACCEPT"sv,
		};
}

bool
UserAuthClient::HandlePacket(SSH::MessageNumber msg,
			     std::span<const std::byte> payload)
{
	assert(connection.IsEncrypted());

	switch (msg) {
	case SSH::MessageNumber::SERVICE_ACCEPT:
		HandleServiceAccept(payload);
		return true;

	case SSH::MessageNumber::USERAUTH_FAILURE:
		if (state != State::USERAUTH_REQUEST)
			throw SSH::Connection::Disconnect{
				SSH::DisconnectReasonCode::PROTOCOL_ERROR,
				"Unexpected USERAUTH_FAILURE"sv,
			};

		state = State::SERVICE_SSH_USERAUTH;
		handler.OnUserAuthFailure();
		return true;

	case SSH::MessageNumber::USERAUTH_SUCCESS:
		if (state != State::USERAUTH_REQUEST)
			throw SSH::Connection::Disconnect{
				SSH::DisconnectReasonCode::PROTOCOL_ERROR,
				"Unexpected USERAUTH_SUCCESS"sv,
			};

		state = State::USERAUTH_SUCCESS;
		handler.OnUserAuthSuccess();
		return true;

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
		if (state != State::USERAUTH_SUCCESS)
			throw SSH::Connection::Disconnect{
				SSH::DisconnectReasonCode::PROTOCOL_ERROR,
				"Unexpected packet"sv,
			};

		return false;

	default:
		return false;
	}
}
