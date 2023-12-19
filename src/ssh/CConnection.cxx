// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "CConnection.hxx"
#include "Channel.hxx"
#include "Serializer.hxx"
#include "MakePacket.hxx"
#include "ParsePacket.hxx"
#include "net/SocketProtocolError.hxx"
#include "util/Cancellable.hxx"

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

/**
 * A placeholder for the real #Channel instance that is being created
 * asynchronously.
 */
class OpeningChannel final : public Channel {
public:
	CancellablePointer cancel_ptr;

	using Channel::Channel;

	~OpeningChannel() noexcept {
		if (cancel_ptr)
			cancel_ptr.Cancel();
	}
};

[[gnu::pure]]
static bool
IsOpeningChannel(const Channel &channel) noexcept
{
	return dynamic_cast<const OpeningChannel *>(&channel) != nullptr;
}

void
CConnection::CloseChannel(Channel &channel)
{
	assert(!IsTombstoneChannel(channel));
	assert(!IsOpeningChannel(channel));

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
	    channels[local_channel] == nullptr ||
	    IsOpeningChannel(*channels[local_channel])) {
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
			 [[maybe_unused]] std::span<const std::byte> payload,
			 [[maybe_unused]] CancellablePointer &cancel_ptr)
{
	throw ChannelOpenFailure{
		ChannelOpenFailureReasonCode::UNKNOWN_CHANNEL_TYPE,
		"Unknown channel type"sv,
	};
}

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static PacketSerializer
MakeChannelOpenConfirmation(uint_least32_t peer_channel,
			    uint_least32_t local_channel,
			    const Channel &channel)
{
	assert(channel.GetPeerChannel() == peer_channel);
	assert(channel.GetLocalChannel() == local_channel);

	PacketSerializer s{MessageNumber::CHANNEL_OPEN_CONFIRMATION};
	s.WriteU32(peer_channel);
	s.WriteU32(local_channel);
	s.WriteU32(channel.GetReceiveWindow()); // TODO
	s.WriteU32(32768);
	channel.SerializeOpenConfirmation(s);
	return s;
}

void
CConnection::AsyncChannelOpenSuccess(Channel &channel) noexcept
{
	assert(!IsTombstoneChannel(channel));
	assert(!IsOpeningChannel(channel));
	assert(channels[channel.GetLocalChannel()] != nullptr);
	assert(IsOpeningChannel(*channels[channel.GetLocalChannel()]));

	const uint_least32_t local_channel = channel.GetLocalChannel();

	auto &opening = *static_cast<OpeningChannel *>(channels[local_channel]);
	channels[local_channel] = nullptr;
	opening.cancel_ptr = {};
	delete &opening;

	try {
		SendPacket(MakeChannelOpenConfirmation(channel.GetPeerChannel(),
						       local_channel,
						       channel));
	} catch (...) {
		OnBufferedError(std::current_exception());
		return;
	}

	channels[local_channel] = &channel;
}

void
CConnection::AsyncChannelOpenFailure(ChannelInit init,
				     ChannelOpenFailureReasonCode reason_code,
				     std::string_view description) noexcept
{
	assert(channels[init.local_channel] != nullptr);
	assert(IsOpeningChannel(*channels[init.local_channel]));

	auto &opening = *static_cast<OpeningChannel *>(channels[init.local_channel]);
	channels[init.local_channel] = nullptr;

	opening.cancel_ptr = {};
	delete &opening;

	try {
		SendPacket(MakeChannelOpenFailure(init.peer_channel, reason_code, description));
	} catch (...) {
		OnBufferedError(std::current_exception());
	}
}

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

	auto *opening = new OpeningChannel(*this, init, 0);
	channels[local_channel] = opening;

	auto channel = OpenChannel(channel_type, init, payload,
				   opening->cancel_ptr);
	if (!channel) {
		// asynchronous open (or already failed)
		assert(channels[local_channel] == nullptr ||
		       IsOpeningChannel(*channels[local_channel]));
		return;
	}

	assert(channel->GetLocalChannel() == local_channel);
	assert(channel->GetPeerChannel() == peer_channel);
	assert(channels[local_channel] != nullptr);
	assert(IsOpeningChannel(*channels[local_channel]));

	SendPacket(MakeChannelOpenConfirmation(peer_channel, local_channel, *channel));

	delete static_cast<OpeningChannel *>(channels[local_channel]);
	channels[local_channel] = channel.release();
} catch (const ChannelOpenFailure &failure) {
	SendPacket(MakeChannelOpenFailure(peer_channel,
					  failure.reason_code,
					  failure.description));
}

inline void
CConnection::HandleChannelOpen(std::span<const std::byte> payload)
{
	const auto p = ParseChannelOpen(payload);

	HandleChannelOpen(p.channel_type, p.peer_channel, p.initial_window_size,
			  p.channel_type_specific_data);
}

inline void
CConnection::HandleChannelWindowAdjust(std::span<const std::byte> payload)
{
	const auto p = ParseChannelWindowAdjust(payload);

	if (p.nbytes == 0)
		throw std::invalid_argument{"Bad window adjustment"};

	auto &channel = GetChannel(p.local_channel);
	channel.OnWindowAdjust(p.nbytes);
}

inline void
CConnection::HandleChannelData(std::span<const std::byte> payload)
{
	const auto p = ParseChannelData(payload);

	auto &channel = GetChannel(p.local_channel);
	if (p.data.size() > channel.GetReceiveWindow())
		throw std::invalid_argument{"Receive window exceeded"};

	channel.OnData(p.data);
}

inline void
CConnection::HandleChannelExtendedData(std::span<const std::byte> payload)
{
	const auto p = ParseChannelExtendedData(payload);

	auto &channel = GetChannel(p.local_channel);
	if (p.data.size() > channel.GetReceiveWindow())
		throw std::invalid_argument{"Receive window exceeded"};

	channel.OnExtendedData(p.data_type, p.data);
}

inline void
CConnection::HandleChannelEof(std::span<const std::byte> payload)
{
	const auto p = ParseChannelEof(payload);

	auto &channel = GetChannel(p.local_channel);
	channel.OnEof();
}

inline void
CConnection::HandleChannelClose(std::span<const std::byte> payload)
{
	const auto p = ParseChannelClose(payload);

	const auto &channel = GetChannel(p.local_channel);
	if (!IsTombstoneChannel(channel))
		SendPacket(MakeChannelClose(channel.GetPeerChannel()));

	delete channels[p.local_channel];
	channels[p.local_channel] = nullptr;
}

inline void
CConnection::HandleChannelRequest(std::span<const std::byte> payload)
{
	const auto p = ParseChannelRequest(payload);

	auto &channel = GetChannel(p.local_channel);
	const uint_least32_t peer_channel = channel.GetPeerChannel();
	const bool success = channel.OnRequest(p.request_type, p.type_specific_data);

	if (p.want_reply) {
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

void
CConnection::OnWriteBlocked() noexcept
{
	Connection::OnWriteBlocked();

	for (auto *i : channels)
		if (i != nullptr)
			i->OnWriteBlocked();
}

void
CConnection::OnWriteUnblocked() noexcept
{
	Connection::OnWriteUnblocked();

	for (auto *i : channels)
		if (i != nullptr)
			i->OnWriteUnblocked();
}

} // namespace SSH
