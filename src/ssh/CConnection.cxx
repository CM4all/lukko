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
	channels[local_channel] = new TombstoneChannel(*this, local_channel,
						       peer_channel);

	delete &channel;
}

inline uint_least32_t
CConnection::AllocateChannelIndex() noexcept
{
	for (uint_least32_t i = 0; i < channels.size(); ++i)
		if (channels[i] == nullptr)
			return i;

	return channels.size();
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

std::unique_ptr<Channel>
CConnection::OpenChannel([[maybe_unused]] std::string_view channel_type,
			 [[maybe_unused]] uint_least32_t local_channel,
			 [[maybe_unused]] uint_least32_t peer_channel)
{
	SendPacket(MakeChannelOpenFailure(peer_channel,
					  ChannelOpenFailureReasonCode::UNKNOWN_CHANNEL_TYPE,
					  "Unknown channel type"sv));

	return {};
}

inline void
CConnection::HandleChannelOpen(std::span<const std::byte> payload)
{
	Deserializer d{payload};

	const auto channel_type = d.ReadString();
	const uint_least32_t peer_channel = d.ReadU32();

	const uint_least32_t local_channel = AllocateChannelIndex();
	if (local_channel >= channels.size()) {
		SendPacket(MakeChannelOpenFailure(peer_channel,
						  ChannelOpenFailureReasonCode::RESOURCE_SHORTAGE,
						  "Too many channels"sv));
		return;
	}

	auto channel = OpenChannel(channel_type, local_channel, peer_channel);
	if (!channel)
		// method must have sent CHANNEL_OPEN_FAILURE
		return;

	assert(channel->GetLocalChannel() == local_channel);
	assert(channel->GetPeerChannel() == peer_channel);

	{
		PacketSerializer s{MessageNumber::CHANNEL_OPEN_CONFIRMATION};
		s.WriteU32(peer_channel);
		s.WriteU32(local_channel);
		s.WriteU32(1 << 20); // TODO
		s.WriteU32(32768);
		channel->SerializeOpenConfirmation(s);
		SendPacket(std::move(s));
	}

	channels[peer_channel] = channel.release();
}

inline void
CConnection::HandleChannelData(std::span<const std::byte> payload)
{
	Deserializer d{payload};
	const uint_least32_t local_channel = d.ReadU32();
	std::span<const std::byte> data = d.ReadLengthEncoded();

	auto &channel = GetChannel(local_channel);
	channel.OnData(data);
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
	switch (msg) {
	case MessageNumber::CHANNEL_OPEN:
		HandleChannelOpen(payload);
		break;

	case MessageNumber::CHANNEL_DATA:
		HandleChannelData(payload);
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
