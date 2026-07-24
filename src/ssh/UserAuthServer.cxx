// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "UserAuthServer.hxx"
#include "Connection.hxx"
#include "MakePacket.hxx"
#include "PacketSerializer.hxx"
#include "ParsePacket.hxx"
#include "util/AllocatedArray.hxx"

using std::string_view_literals::operator""sv;

namespace SSH {

UserAuthServer::UserAuthServer(Connection &_connection,
			       UserAuthServerHandler &_handler) noexcept
	:connection(_connection),
	 handler(_handler)
{
	assert(connection.IsEncrypted());

	connection.AddHandler(*this);
}

UserAuthServer::~UserAuthServer() noexcept = default;

inline void
UserAuthServer::HandleServiceRequest(std::span<const std::byte> payload)
{
	const auto p = ParseServiceRequest(payload);

	if (p.service_name == "ssh-userauth"sv) {
		have_service_userauth = true;
		connection.SendPacket(MakeServiceAccept(p.service_name));
	} else {
		handler.OnUnsupportedService();
		throw Connection::Disconnect{
			DisconnectReasonCode::SERVICE_NOT_AVAILABLE,
			"Unsupported service"sv,
		};
	}
}

inline void
UserAuthServer::OnUserAuthCompletion(std::exception_ptr &&error) noexcept
{
	if (error) {
		try {
			std::rethrow_exception(std::move(error));
		} catch (const Connection::Disconnect &d) {
			connection.DoDisconnect(d.reason_code, d.msg);
		} catch (...) {
			connection.CloseError(std::current_exception());
		}
	} else if (connection.IsAuthenticated()) {
		handler.OnUserAuthCompletion();
	}
}

inline void
UserAuthServer::HandleUserauthRequest(std::span<const std::byte> payload)
{
	assert(!occupied_task);

	if (connection.IsAuthenticated())
		/* RFC 4252 section 5.1: "When
		   SSH_MSG_USERAUTH_SUCCESS has been sent, any further
		   authentication requests received after that SHOULD
		   be silently ignored" */
		return;

	if (!have_service_userauth) {
		throw Connection::Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"Service ssh-userauth not requested"sv
		};
	}

	/* the payload is owned by the caller, therefore we need to
	   duplicate it into an AllocatedArray owned by the coroutine,
	   so the coroutine can keep using it after this method
	   returns */
	occupied_task = handler.OnUserAuthRequest(AllocatedArray{payload});

	/* we're using EagerInvokeTask here because early errors get
	   rethrown out of this method instead of being passed to
	   OnUserAuthCompletion(); the latter would destroy this
	   Connection instance, but this method wouldn't know and
	   would continue accessing it */
	occupied_task.Start(BIND_THIS_METHOD(OnUserAuthCompletion));
}

/**
 * Is this message allowed while the connection is "occupied"?
 */
static constexpr bool
IsAllowedWhileOccupied(MessageNumber msg) noexcept
{
	using enum MessageNumber;
	switch (msg) {
	case DISCONNECT:
	case IGNORE:
	case NEWCOMPRESS:
	case KEXINIT:
	case NEWKEYS:
	case ECDH_KEX_INIT:
	case ECDH_KEX_INIT_REPLY:
		return true;

	default:
		break;
	}

	return false;
}

bool
UserAuthServer::HandlePacket(MessageNumber msg,
			     std::span<const std::byte> payload)
{
	assert(connection.IsEncrypted());

	if (IsOccupied() && !IsAllowedWhileOccupied(msg))
		throw Connection::Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"Occupied"sv
		};

	switch (msg) {
	case MessageNumber::SERVICE_REQUEST:
		HandleServiceRequest(payload);
		return true;

	case MessageNumber::USERAUTH_REQUEST:
		HandleUserauthRequest(payload);
		return true;

	default:
		return false;
	}
}

} // namespace SSH
