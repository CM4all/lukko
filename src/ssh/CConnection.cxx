// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "CConnection.hxx"
#include "Channel.hxx"
#include "Serializer.hxx"
#include "Deserializer.hxx"
#include "MakePacket.hxx"
#include "net/SocketProtocolError.hxx"

using std::string_view_literals::operator""sv;

namespace SSH {

class Channel;

CConnection::~CConnection() noexcept
{
	for (auto *i : channels)
		delete i;
}

/**
 * A placeholder for the real #Channel instance after we sent
 * CHANNEL_CLOSE, until we receive the peer's CHANNEL_CLOSE.
 */
class TombstoneChannel final : public Channel {
public:
	using Channel::Channel;
};

[[gnu::pure]]
static bool
IsTombstoneChannel(const Channel &channel) noexcept
{
	return dynamic_cast<const TombstoneChannel *>(&channel) != nullptr;
}

void
CConnection::CloseChannel(Channel &channel) noexcept
{
	assert(!IsTombstoneChannel(channel));

	const uint_least32_t local_channel = channel.GetLocalChannel();
	const uint_least32_t peer_channel = channel.GetPeerChannel();
	assert(local_channel < channels.size());
	assert(channels[local_channel] == &channel);

	SendPacket(MakeChannelClose(peer_channel));

	const ChannelInit init{
		.local_channel = local_channel,
		.peer_channel = peer_channel,
		.send_window = channel.GetSendWindow(),
	};

	channels[local_channel] = new TombstoneChannel(*this, init,
						       channel.GetReceiveWindow());

	delete &channel;
}

inline uint_least32_t
CConnection::AllocateChannelIndex()
{
	for (uint_least32_t i = 0; i < channels.size(); ++i)
		if (channels[i] == nullptr)
			return i;

	throw ChannelOpenFailure{
		ChannelOpenFailureReasonCode::RESOURCE_SHORTAGE,
		"Too many channels"sv,
	};
}

Channel &
CConnection::GetChannel(uint_least32_t local_channel)
{
	if (local_channel >= channels.size() ||
	    channels[local_channel] == nullptr) {
		throw Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"Bad channel"sv,
		};
	}

	return *channels[local_channel];
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsuggest-attribute=noreturn"
#endif

std::unique_ptr<Channel>
CConnection::OpenChannel([[maybe_unused]] std::string_view channel_type,
			 [[maybe_unused]] ChannelInit init,
			 [[maybe_unused]] std::span<const std::byte> payload)
{
	throw ChannelOpenFailure{
		ChannelOpenFailureReasonCode::UNKNOWN_CHANNEL_TYPE,
		"Unknown channel type"sv,
	};
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

inline void
CConnection::HandleChannelOpen(std::string_view channel_type,
			       uint_least32_t peer_channel,
			       uint_least32_t initial_window_size,
			       std::span<const std::byte> payload)
try {
	const uint_least32_t local_channel = AllocateChannelIndex();

	const ChannelInit init{
		.local_channel = local_channel,
		.peer_channel = peer_channel,
		.send_window = initial_window_size,
	};

	auto channel = OpenChannel(channel_type, init, payload);
	assert(channel);

	assert(channel->GetLocalChannel() == local_channel);
	assert(channel->GetPeerChannel() == peer_channel);

	{
		PacketSerializer s{MessageNumber::CHANNEL_OPEN_CONFIRMATION};
		s.WriteU32(peer_channel);
		s.WriteU32(local_channel);
		s.WriteU32(channel->GetReceiveWindow()); // TODO
		s.WriteU32(32768);
		channel->SerializeOpenConfirmation(s);
		SendPacket(std::move(s));
	}

	channels[local_channel] = channel.release();
} catch (const ChannelOpenFailure &failure) {
	SendPacket(MakeChannelOpenFailure(peer_channel,
					  failure.reason_code,
					  failure.description));
	}

inline void
CConnection::HandleChannelOpen(std::span<const std::byte> payload)
{
	Deserializer d{payload};

	const auto channel_type = d.ReadString();
	const uint_least32_t peer_channel = d.ReadU32();
	const uint_least32_t initial_window_size = d.ReadU32();
	d.ReadU32(); // TODO maximum packet size

	HandleChannelOpen(channel_type, peer_channel, initial_window_size,
			  d.GetRest());
}

inline void
CConnection::HandleChannelWindowAdjust(std::span<const std::byte> payload)
{
	Deserializer d{payload};
	const uint_least32_t local_channel = d.ReadU32();
	const uint_least32_t nbytes = d.ReadU32();

	if (nbytes == 0)
		throw std::invalid_argument{"Bad window adjustment"};

	auto &channel = GetChannel(local_channel);
	channel.OnWindowAdjust(nbytes);
}

inline void
CConnection::HandleChannelData(std::span<const std::byte> payload)
{
	Deserializer d{payload};
	const uint_least32_t local_channel = d.ReadU32();
	std::span<const std::byte> data = d.ReadLengthEncoded();

	auto &channel = GetChannel(local_channel);
	if (data.size() > channel.GetReceiveWindow())
		throw std::invalid_argument{"Receive window exceeded"};

	channel.OnData(data);
}

inline void
CConnection::HandleChannelExtendedData(std::span<const std::byte> payload)
{
	Deserializer d{payload};
	const uint_least32_t local_channel = d.ReadU32();
	const auto data_type = static_cast<ChannelExtendedDataType>(d.ReadU32());
	std::span<const std::byte> data = d.ReadLengthEncoded();

	auto &channel = GetChannel(local_channel);
	if (data.size() > channel.GetReceiveWindow())
		throw std::invalid_argument{"Receive window exceeded"};

	channel.OnExtendedData(data_type, data);
}

inline void
CConnection::HandleChannelEof(std::span<const std::byte> payload)
{
	Deserializer d{payload};
	const uint_least32_t local_channel = d.ReadU32();

	auto &channel = GetChannel(local_channel);
	channel.OnEof();
}

inline void
CConnection::HandleChannelClose(std::span<const std::byte> payload)
{
	Deserializer d{payload};
	const uint_least32_t local_channel = d.ReadU32();

	const auto &channel = GetChannel(local_channel);
	if (!IsTombstoneChannel(channel))
		SendPacket(MakeChannelClose(channel.GetPeerChannel()));

	delete channels[local_channel];
	channels[local_channel] = nullptr;
}

inline void
CConnection::HandleChannelRequest(std::span<const std::byte> payload)
{
	Deserializer d{payload};
	const uint_least32_t local_channel = d.ReadU32();
	const std::string_view request_type = d.ReadString();
	const bool want_reply = d.ReadBool();

	auto &channel = GetChannel(local_channel);
	const uint_least32_t peer_channel = channel.GetPeerChannel();
	const bool success = channel.OnRequest(request_type, d.GetRest());

	if (want_reply) {
		PacketSerializer s{
			success
			? MessageNumber::CHANNEL_SUCCESS
			: MessageNumber::CHANNEL_FAILURE,
		};

		s.WriteU32(peer_channel);
		SendPacket(std::move(s));
	}
}

void
CConnection::HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload)
{
	if (!IsEncrypted() || !IsAuthenticated())
		return Connection::HandlePacket(msg, payload);

	switch (msg) {
	case MessageNumber::CHANNEL_OPEN:
		HandleChannelOpen(payload);
		break;

	case MessageNumber::CHANNEL_WINDOW_ADJUST:
		HandleChannelWindowAdjust(payload);
		break;

	case MessageNumber::CHANNEL_DATA:
		HandleChannelData(payload);
		break;

	case MessageNumber::CHANNEL_EXTENDED_DATA:
		HandleChannelExtendedData(payload);
		break;

	case MessageNumber::CHANNEL_EOF:
		HandleChannelEof(payload);
		break;

	case MessageNumber::CHANNEL_CLOSE:
		HandleChannelClose(payload);
		break;

	case MessageNumber::CHANNEL_REQUEST:
		HandleChannelRequest(payload);
		break;

	default:
		Connection::HandlePacket(msg, payload);
	}
}

} // namespace SSH
