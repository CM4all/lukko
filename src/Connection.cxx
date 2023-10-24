// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Connection.hxx"
#include "Instance.hxx"
#include "Listener.hxx"
#include "SessionChannel.hxx"
#include "ssh/Protocol.hxx"
#include "ssh/MakePacket.hxx"
#include "ssh/Deserializer.hxx"
#include "ssh/Channel.hxx"
#include "net/UniqueSocketDescriptor.hxx"

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
		       const KeyList &_host_keys)
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

inline void
Connection::HandleUserauthRequest(std::span<const std::byte> payload)
{
	SSH::Deserializer d{payload};
	const auto new_username = d.ReadString();
	fmt::print(stderr, "Userauth '{}'\n", new_username);

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

	username.assign(new_username);

	SendPacket(SSH::PacketSerializer{SSH::MessageNumber::USERAUTH_SUCCESS});
}

inline void
Connection::HandlePacket(SSH::MessageNumber msg,
			 std::span<const std::byte> payload)
{
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
