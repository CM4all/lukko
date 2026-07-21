// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "CSupport.hxx"
#include "CFactory.hxx"
#include "Connection.hxx"
#include "Channel.hxx"
#include "Serializer.hxx"
#include "MakePacket.hxx"
#include "ParsePacket.hxx"
#include "net/SocketProtocolError.hxx"
#include "util/Cancellable.hxx"

#include <cassert>

using std::string_view_literals::operator""sv;

namespace SSH {

class Channel;

ChannelSupport::ChannelSupport(Connection &_connection,
			       ChannelHandler &_handler) noexcept
	:connection(_connection),
	 channel_handler(_handler)
{
	connection.AddHandler(*this);
}

ChannelSupport::~ChannelSupport() noexcept
{
	for (auto *i : channels)
		delete i;
}

void
ChannelSupport::SendPacket(PacketSerializer &&s) noexcept
{
	connection.SendPacket(std::move(s));
}

/**
 * A placeholder for the real #Channel instance that is being
 * requested from the peer asynchronously.
 */
class RequestedChannel final : public Channel, Cancellable {
	ChannelFactory &factory;

	bool canceled = false;

public:
	RequestedChannel(ChannelSupport &_connection,
			 uint_least32_t _local_channel,
			 ChannelFactory &_factory,
			 CancellablePointer &cancel_ptr) noexcept
		:Channel(_connection,
			 { .local_channel = _local_channel },
			 0),
		 factory(_factory)
	{
		cancel_ptr = *this;
	}

	~RequestedChannel() noexcept override {
		if (!canceled)
			factory.OnChannelCancel();
	}

	std::unique_ptr<Channel> OnChannelOpenConfirmation(const ChannelOpenConfirmation &p) {
		assert(p.local_channel == GetLocalChannel());

		if (canceled) {
			delete this;
			return {};
		}

		auto &_factory = factory;
		delete this;
		return _factory.CreateChannel({
				.local_channel = p.local_channel,
				.peer_channel = p.peer_channel,
				.send_window = p.initial_window_size,
			});
	}

	void OnChannelOpenFailure(ChannelOpenFailureReasonCode code,
				  std::string_view description) noexcept {
		if (canceled) {
			delete this;
			return;
		}

		auto &_factory = factory;
		delete this;
		_factory.OnChannelOpenFailure(code, description);
	}

private:
	/* virtual methods from class Cancellable */
	void Cancel() noexcept override {
		assert(!canceled);
		canceled = true;
	}
};

[[gnu::pure]]
static bool
IsRequestedChannel(const Channel &channel) noexcept
{
	return dynamic_cast<const RequestedChannel *>(&channel) != nullptr;
}

void
ChannelSupport::OpenChannel(std::string_view channel_type,
			 uint_least32_t initial_window_size,
			 ChannelFactory &factory,
			 CancellablePointer &cancel_ptr)
{
	// TODO what if this throws ChannelOpenFailure?
	const uint_least32_t local_channel = AllocateChannelIndex();

	{
		PacketSerializer s{MessageNumber::CHANNEL_OPEN};
		s.WriteString(channel_type);
		s.WriteU32(local_channel);
		s.WriteU32(initial_window_size);
		s.WriteU32(MAXIMUM_PACKET_SIZE);
		factory.SerializeOpen(s);
		connection.SendPacket(std::move(s));
	}

	auto *requested = new RequestedChannel(*this, local_channel,
					       factory, cancel_ptr);
	channels[local_channel] = requested;
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
ChannelSupport::CloseChannel(Channel &channel) noexcept
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
ChannelSupport::AllocateChannelIndex()
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
ChannelSupport::GetChannel(uint_least32_t local_channel)
{
	if (local_channel >= channels.size() ||
	    channels[local_channel] == nullptr ||
	    IsRequestedChannel(*channels[local_channel]) ||
	    IsOpeningChannel(*channels[local_channel])) {
		throw Connection::Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"Bad channel"sv,
		};
	}

	return *channels[local_channel];
}

RequestedChannel &
ChannelSupport::PopRequestedChannel(uint_least32_t local_channel)
{
	if (local_channel >= channels.size() ||
	    channels[local_channel] == nullptr ||
	    !IsRequestedChannel(*channels[local_channel])) {
		throw Connection::Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"Bad channel"sv,
		};
	}

	return *static_cast<RequestedChannel *>(std::exchange(channels[local_channel], nullptr));
}

static PacketSerializer
MakeChannelOpenConfirmation(uint_least32_t peer_channel,
			    uint_least32_t local_channel,
			    uint_least32_t maximum_packet_size,
			    const Channel &channel)
{
	assert(channel.GetPeerChannel() == peer_channel);
	assert(channel.GetLocalChannel() == local_channel);

	PacketSerializer s{MessageNumber::CHANNEL_OPEN_CONFIRMATION};
	s.WriteU32(peer_channel);
	s.WriteU32(local_channel);
	s.WriteU32(channel.GetReceiveWindow()); // TODO
	s.WriteU32(maximum_packet_size);
	channel.SerializeOpenConfirmation(s);
	return s;
}

void
ChannelSupport::AsyncChannelOpenSuccess(Channel &channel) noexcept
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

	SendPacket(MakeChannelOpenConfirmation(channel.GetPeerChannel(),
					       local_channel,
					       MAXIMUM_PACKET_SIZE,
					       channel));

	channels[local_channel] = &channel;
}

void
ChannelSupport::AsyncChannelOpenFailure(ChannelInit init,
				     ChannelOpenFailureReasonCode reason_code,
				     std::string_view description) noexcept
{
	assert(channels[init.local_channel] != nullptr);
	assert(IsOpeningChannel(*channels[init.local_channel]));

	auto &opening = *static_cast<OpeningChannel *>(channels[init.local_channel]);
	channels[init.local_channel] = nullptr;

	opening.cancel_ptr = {};
	delete &opening;

	SendPacket(MakeChannelOpenFailure(init.peer_channel, reason_code, description));
}

inline void
ChannelSupport::HandleChannelOpen(std::string_view channel_type,
			       uint_least32_t peer_channel,
			       uint_least32_t initial_window_size,
			       std::span<const std::byte> payload)
{
	const uint_least32_t local_channel = AllocateChannelIndex();

	const ChannelInit init{
		.local_channel = local_channel,
		.peer_channel = peer_channel,
		.send_window = initial_window_size,
	};

	auto *opening = new OpeningChannel(*this, init, 0);
	channels[local_channel] = opening;

	std::unique_ptr<Channel> channel;

	try {
		channel = channel_handler.CreateChannel(channel_type, init, payload,
							opening->cancel_ptr);
	} catch (const ChannelOpenFailure &failure) {
		assert(channels[local_channel] == opening);
		channels[local_channel] = nullptr;
		delete opening;

		SendPacket(MakeChannelOpenFailure(peer_channel,
						  failure.reason_code,
						  failure.description));
		return;
	}

	if (!channel) {
		// asynchronous open (or already failed)
		assert(channels[local_channel] == nullptr ||
		       IsOpeningChannel(*channels[local_channel]));
		return;
	}

	assert(channel->GetLocalChannel() == local_channel);
	assert(channel->GetPeerChannel() == peer_channel);
	assert(channels[local_channel] == opening);
	assert(IsOpeningChannel(*channels[local_channel]));

	SendPacket(MakeChannelOpenConfirmation(peer_channel, local_channel,
					       MAXIMUM_PACKET_SIZE,
					       *channel));

	assert(channels[local_channel] == opening);
	channels[local_channel] = channel.release();
	delete opening;
}

inline void
ChannelSupport::HandleChannelOpen(std::span<const std::byte> payload)
{
	const auto p = ParseChannelOpen(payload);

	HandleChannelOpen(p.channel_type, p.peer_channel, p.initial_window_size,
			  p.channel_type_specific_data);
}

inline void
ChannelSupport::HandleChannelOpenConfirmation(std::span<const std::byte> payload)
{
	const auto p = ParseChannelOpenConfirmation(payload);
	auto &requested_channel = PopRequestedChannel(p.local_channel);

	auto channel = requested_channel.OnChannelOpenConfirmation(p);

	if (!channel) {
		/* was canceled - tell the peer to close the channel
		   that was just confirmed */

		SendPacket(MakeChannelClose(p.peer_channel));

		const ChannelInit init{
			.local_channel = p.local_channel,
			.peer_channel = p.peer_channel,
			.send_window = p.initial_window_size,
		};

		channels[p.local_channel] = new TombstoneChannel(*this, init,
								 p.initial_window_size);
		return;
	}

	channels[p.local_channel] = channel.release();
}

inline void
ChannelSupport::HandleChannelOpenFailure(std::span<const std::byte> payload)
{
	const auto p = ParseChannelOpenFailure(payload);
	auto &channel = PopRequestedChannel(p.local_channel);

	channel.OnChannelOpenFailure(p.reason_code, p.description);
}

inline void
ChannelSupport::HandleChannelWindowAdjust(std::span<const std::byte> payload)
{
	const auto p = ParseChannelWindowAdjust(payload);

	if (p.nbytes == 0)
		throw std::invalid_argument{"Bad window adjustment"};

	auto &channel = GetChannel(p.local_channel);
	channel.OnWindowAdjust(p.nbytes);
}

inline void
ChannelSupport::HandleChannelData(std::span<const std::byte> payload)
{
	const auto p = ParseChannelData(payload);

	auto &channel = GetChannel(p.local_channel);
	if (p.data.size() > channel.GetReceiveWindow())
		throw std::invalid_argument{"Receive window exceeded"};

	channel.OnData(p.data);
}

inline void
ChannelSupport::HandleChannelExtendedData(std::span<const std::byte> payload)
{
	const auto p = ParseChannelExtendedData(payload);

	auto &channel = GetChannel(p.local_channel);
	if (p.data.size() > channel.GetReceiveWindow())
		throw std::invalid_argument{"Receive window exceeded"};

	channel.OnExtendedData(p.data_type, p.data);
}

inline void
ChannelSupport::HandleChannelEof(std::span<const std::byte> payload)
{
	const auto p = ParseChannelEof(payload);

	auto &channel = GetChannel(p.local_channel);
	channel.OnEof();
}

inline void
ChannelSupport::HandleChannelClose(std::span<const std::byte> payload)
{
	const auto p = ParseChannelClose(payload);

	const auto &channel = GetChannel(p.local_channel);
	if (!IsTombstoneChannel(channel))
		SendPacket(MakeChannelClose(channel.GetPeerChannel()));

	delete channels[p.local_channel];
	channels[p.local_channel] = nullptr;
}

inline void
ChannelSupport::HandleChannelRequest(std::span<const std::byte> payload)
{
	const auto p = ParseChannelRequest(payload);

	auto &channel = GetChannel(p.local_channel);
	channel.HandleRequest(p.request_type, p.type_specific_data, p.want_reply);
}

bool
ChannelSupport::HandlePacket(MessageNumber msg,
			     std::span<const std::byte> payload)
{
	if (!connection.IsEncrypted() || !connection.IsAuthenticated())
		return false;

	switch (msg) {
	case MessageNumber::CHANNEL_OPEN:
		HandleChannelOpen(payload);
		return true;

	case MessageNumber::CHANNEL_OPEN_CONFIRMATION:
		HandleChannelOpenConfirmation(payload);
		return true;

	case MessageNumber::CHANNEL_OPEN_FAILURE:
		HandleChannelOpenFailure(payload);
		return true;

	case MessageNumber::CHANNEL_WINDOW_ADJUST:
		HandleChannelWindowAdjust(payload);
		return true;

	case MessageNumber::CHANNEL_DATA:
		HandleChannelData(payload);
		return true;

	case MessageNumber::CHANNEL_EXTENDED_DATA:
		HandleChannelExtendedData(payload);
		return true;

	case MessageNumber::CHANNEL_EOF:
		HandleChannelEof(payload);
		return true;

	case MessageNumber::CHANNEL_CLOSE:
		HandleChannelClose(payload);
		return true;

	case MessageNumber::CHANNEL_REQUEST:
		HandleChannelRequest(payload);
		return true;

	default:
		return false;
	}
}

void
ChannelSupport::OnWriteBlocked() noexcept
{
	for (auto *i : channels)
		if (i != nullptr)
			i->OnWriteBlocked();
}

void
ChannelSupport::OnWriteUnblocked() noexcept
{
	for (auto *i : channels)
		if (i != nullptr)
			i->OnWriteUnblocked();
}

void
ChannelSupport::OnDisconnecting([[maybe_unused]] DisconnectReasonCode reason_code,
				[[maybe_unused]] std::string_view msg) noexcept
{
	/* delete all channels so they don't try to do any I/O while
           we're waiting for the DISCONNECT to be flushed */
	for (auto &i : channels) {
		delete i;
		i = nullptr;
	}
}

} // namespace SSH
