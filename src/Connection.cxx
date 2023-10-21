// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Connection.hxx"
#include "Instance.hxx"
#include "ssh/Protocol.hxx"
#include "ssh/MakePacket.hxx"
#include "ssh/Deserializer.hxx"
#include "net/UniqueSocketDescriptor.hxx"

#include <fmt/core.h>

using std::string_view_literals::operator""sv;

Connection::Connection(Instance &_instance, UniqueSocketDescriptor _fd,
		       const Key &_host_key)
	:SSH::Connection(_instance.GetEventLoop(), std::move(_fd),
			 _host_key),
	 instance(_instance), logger(instance.GetLogger())
{
}

Connection::~Connection() noexcept = default;

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
	(void)payload;

	SendPacket(SSH::PacketSerializer{SSH::MessageNumber::USERAUTH_SUCCESS});
	SendPacket(SSH::MakeUserauthBanner("Hello, world!\n"));
}

inline void
Connection::HandleChannelOpen(std::span<const std::byte> payload)
{
	SSH::Deserializer d{payload};

	const auto channel_type = d.ReadString();
	const uint_least32_t sender_channel = d.ReadU32();

	fmt::print(stderr, "ChannelOpen type={} sender_channel={}\n", channel_type, sender_channel);

	SendPacket(SSH::MakeChannelOpenFailure(sender_channel,
					       SSH::ChannelOpenFailureReasonCode::ADMINISTRATIVELY_PROHIBITED,
					       "No!"sv));
}

inline void
Connection::HandlePacket(SSH::MessageNumber msg,
			 std::span<const std::byte> payload)
{
	fmt::print(stderr, "Packet msg={} size={}\n", (int)msg, payload.size());

	switch (msg) {
	case SSH::MessageNumber::SERVICE_REQUEST:
		HandleServiceRequest(payload);
		break;

	case SSH::MessageNumber::USERAUTH_REQUEST:
		HandleUserauthRequest(payload);
		break;

	case SSH::MessageNumber::CHANNEL_OPEN:
		HandleChannelOpen(payload);
		break;

	default:
		SSH::Connection::HandlePacket(msg, payload);
	}
}

void
Connection::OnBufferedError(std::exception_ptr e) noexcept
{
	logger(1, e);
	SSH::Connection::OnBufferedError(std::move(e));
}
