// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Connection.hxx"
#include "Instance.hxx"
#include "Listener.hxx"
#include "SessionChannel.hxx"
#include "key/Parser.hxx"
#include "key/Key.hxx"
#include "ssh/Protocol.hxx"
#include "ssh/MakePacket.hxx"
#include "ssh/Deserializer.hxx"
#include "ssh/Channel.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "util/CharUtil.hxx"
#include "util/StringVerify.hxx"

#ifdef ENABLE_TRANSLATION
#include "translation/LoginGlue.hxx"
#include "translation/Response.hxx"
#include "AllocatorPtr.hxx"
#endif // ENABLE_TRANSLATION

#include <fmt/core.h>

using std::string_view_literals::operator""sv;

#ifdef ENABLE_TRANSLATION

struct Connection::Translation {
	Allocator alloc;
	TranslateResponse response;

	Translation(Allocator &&_alloc,
		    TranslateResponse &&_response) noexcept
		:alloc(std::move(_alloc)),
		 response(std::move(_response)) {}
};

#endif // ENABLE_TRANSLATION

Connection::Connection(Instance &_instance, Listener &_listener,
		       UniqueSocketDescriptor _fd,
		       const SecretKeyList &_host_keys)
	:SSH::CConnection(_instance.GetEventLoop(), std::move(_fd),
			  _host_keys),
	 instance(_instance), listener(_listener),
	 logger(instance.GetLogger())
{
}

Connection::~Connection() noexcept = default;

#ifdef ENABLE_TRANSLATION

const TranslateResponse *
Connection::GetTranslationResponse() const noexcept
{
	return translation
		? &translation->response
		: nullptr;
}

#endif

std::unique_ptr<SSH::Channel>
Connection::OpenChannel(std::string_view channel_type,
			SSH::ChannelInit init)
{
	fmt::print(stderr, "ChannelOpen type={} local_channel={} peer_channel={}\n",
		   channel_type, init.local_channel, init.peer_channel);

	if (channel_type == "session"sv) {
		CConnection &connection = *this;
		return std::make_unique<SessionChannel>(instance.GetSpawnService(),
							connection, init);
	} else
		return SSH::CConnection::OpenChannel(channel_type, init);
}

inline void
Connection::HandleServiceRequest(std::span<const std::byte> payload)
{
	SSH::Deserializer d{payload};

	const auto service = d.ReadString();
	fmt::print(stderr, "ServiceRequest '{}'\n", service);

	if (service == "ssh-userauth"sv) {
		SendPacket(SSH::MakeServiceAccept(service));
	} else
		throw Disconnect{SSH::DisconnectReasonCode::SERVICE_NOT_AVAILABLE,
			"Unsupported service"sv};
}

static bool
IsValidUsername(std::string_view username) noexcept
{
	return username.size() <= 255 && CheckCharsNonEmpty(username, [](char ch){
		return IsAlphaNumericASCII(ch) || ch == '-' || ch == '_';
	});
}

inline void
Connection::HandleUserauthRequest(std::span<const std::byte> payload)
{
	if (IsAuthenticated())
		/* RFC 4252 section 5.1: "When
		   SSH_MSG_USERAUTH_SUCCESS has been sent, any further
		   authentication requests received after that SHOULD
		   be silently ignored" */
		return;

	SSH::Deserializer d{payload};
	const auto new_username = d.ReadString();
	const auto service_name = d.ReadString();
	const auto method_name = d.ReadString();

	fmt::print(stderr, "Userauth '{}' service='{}' method='{}'\n",
		   new_username, service_name, method_name);

	if (service_name != "ssh-connection"sv) {
		SendPacket(SSH::MakeUserauthFailure({}, false));
		return;
	}

	if (!IsValidUsername(new_username))
		throw Disconnect{
			SSH::DisconnectReasonCode::ILLEGAL_USER_NAME,
			"Illegal user name"sv,
		};

#ifdef ENABLE_TRANSLATION
	if (const char *translation_server = instance.GetTranslationServer()) {
		Allocator alloc;
		auto response = TranslateLogin(alloc, translation_server,
					       "ssh"sv, listener.GetTag(),
					       new_username, {});

		if (response.status != HttpStatus{}) {
			SendPacket(SSH::MakeUserauthFailure({}, false));
			return;
		}

		translation = std::make_unique<Translation>(std::move(alloc),
							    std::move(response));
	}
#endif // ENABLE_TRANSLATION

	if (method_name == "publickey"sv) {
		const bool with_signature = d.ReadBool();
		const auto public_key_algorithm = d.ReadString();
		const auto public_key_blob = d.ReadLengthEncoded();
		fmt::print(stderr, "  public_key_algorithm='{}'\n",
			   public_key_algorithm);

		std::unique_ptr<PublicKey> public_key;

		try {
			public_key = ParsePublicKeyBlob(public_key_blob);
		} catch (...) {
			logger(1, "Failed to parse the client's public key: ",
			       std::current_exception());
			SendPacket(SSH::MakeUserauthFailure("publickey"sv, false));
			return;
		}

		// TODO check if this key is acceptable

		if (!with_signature) {
			SendPacket(SSH::MakeUserauthPkOk(public_key_algorithm,
							 public_key_blob));
			return;
		} else {
			const auto signature = d.ReadLengthEncoded();

			try {
				SSH::Serializer s;
				s.WriteLengthEncoded(GetSessionId());
				s.WriteU8(static_cast<uint_least8_t>(SSH::MessageNumber::USERAUTH_REQUEST));
				s.WriteString(new_username);
				s.WriteString(service_name);
				s.WriteString(method_name);
				s.WriteBool(true);
				s.WriteString(public_key_algorithm);
				s.WriteLengthEncoded(public_key_blob);

				if (!public_key->Verify(s.Finish(), signature)) {
					SendPacket(SSH::MakeUserauthFailure("publickey"sv, false));
					return;
				}
			} catch (...) {
				logger(1, "Failed to verify the client's public key: ",
				       std::current_exception());
				SendPacket(SSH::MakeUserauthFailure("publickey"sv, false));
				return;
			}
		}
	} else {
		SendPacket(SSH::MakeUserauthFailure("publickey"sv, false));
		return;
	}

	username.assign(new_username);

	SetAuthenticated();
	SendPacket(SSH::PacketSerializer{SSH::MessageNumber::USERAUTH_SUCCESS});
}

inline void
Connection::HandlePacket(SSH::MessageNumber msg,
			 std::span<const std::byte> payload)
{
	if (!IsEncrypted())
		return CConnection::HandlePacket(msg, payload);

	switch (msg) {
	case SSH::MessageNumber::SERVICE_REQUEST:
		HandleServiceRequest(payload);
		break;

	case SSH::MessageNumber::USERAUTH_REQUEST:
		HandleUserauthRequest(payload);
		break;

	default:
		SSH::CConnection::HandlePacket(msg, payload);
	}
}

void
Connection::OnBufferedError(std::exception_ptr e) noexcept
{
	logger(1, e);
	SSH::CConnection::OnBufferedError(std::move(e));
}
