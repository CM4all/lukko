// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "Channel.hxx"
#include "CConnection.hxx"
#include "Serializer.hxx"
#include "MakePacket.hxx"
#include "co/InvokeTask.hxx"
#include "co/Task.hxx"
#include "util/DeleteDisposer.hxx"

using std::string_view_literals::operator""sv;

namespace SSH {

/**
 * A request that is still running as C++ coroutine.
 */
class Channel::PendingRequest : public IntrusiveListHook<> {
	Channel &channel;

	/**
	 * The actual coroutine.
	 */
	Co::EagerInvokeTask invoke_task;

	const bool want_reply;

	bool success;

public:
	PendingRequest(Channel &_channel, bool _want_reply,
		       Co::EagerTask<bool> &&_task)
		:channel(_channel),
		 invoke_task(Run(std::move(_task))),
		 want_reply(_want_reply) {}

	bool IsDone() const noexcept {
		return !invoke_task;
	}

	bool WantsReply() const noexcept {
		return want_reply;
	}

	bool WasSuccessful() const noexcept {
		assert(IsDone());

		return success;
	}

	void Start() noexcept {
		invoke_task.Start(BIND_THIS_METHOD(OnCompletion));
	}

private:
	Co::EagerInvokeTask Run(Co::EagerTask<bool> task) {
		success = co_await task;
	}

	void OnCompletion(std::exception_ptr &&error) noexcept {
		if (error)
			success = false;

		channel.OnRequestDone(*this, std::move(error));
	}
};

Channel::Channel(CConnection &_connection, ChannelInit init,
		 std::size_t _receive_window) noexcept
	:connection(_connection),
	 local_channel(init.local_channel),
	 peer_channel(init.peer_channel),
	 receive_window(_receive_window),
	 send_window(init.send_window) {}

Channel::~Channel() noexcept
{
	pending_requests.clear_and_dispose(DeleteDisposer{});
}

void
Channel::Close() noexcept
{
	connection.CloseChannel(*this);
}

std::size_t
Channel::ConsumeReceiveWindow(std::size_t nbytes) noexcept
{
	assert(nbytes <= receive_window);

	return receive_window -= nbytes;
}

void
Channel::SendWindowAdjust(uint_least32_t nbytes) noexcept
{
	assert(nbytes > 0);
	assert(nbytes <= SIZE_MAX - receive_window);

	connection.SendPacket(MakeChannelWindowAdjust(GetPeerChannel(), nbytes));

	receive_window += nbytes;
}

void
Channel::SendData(std::span<const std::byte> src)
{
	assert(src.size() <= send_window);

	PacketSerializer s{MessageNumber::CHANNEL_DATA};
	s.WriteU32(GetPeerChannel());
	s.WriteLengthEncoded(src);
	connection.SendPacket(std::move(s));

	send_window -= src.size();
}

void
Channel::SendExtendedData(ChannelExtendedDataType data_type,
			  std::span<const std::byte> src)
{
	assert(src.size() <= send_window);

	PacketSerializer s{MessageNumber::CHANNEL_EXTENDED_DATA};
	s.WriteU32(GetPeerChannel());
	s.WriteU32(static_cast<uint_least32_t>(data_type));
	s.WriteLengthEncoded(src);
	connection.SendPacket(std::move(s));

	send_window -= src.size();
}

void
Channel::SendStderr(std::span<const std::byte> src)
{
	SendExtendedData(ChannelExtendedDataType::STDERR, src);
}

void
Channel::SendEof() noexcept
{
	PacketSerializer s{MessageNumber::CHANNEL_EOF};
	s.WriteU32(GetPeerChannel());
	connection.SendPacket(std::move(s));
}

void
Channel::SendExitStatus(uint_least32_t exit_status) noexcept
{
	auto s = MakeChannelReqest(GetPeerChannel(), "exit-status"sv, false);
	s.WriteU32(exit_status);
	connection.SendPacket(std::move(s));
}

void
Channel::SendExitSignal(std::string_view signal_name, bool core_dumped,
			std::string_view error_message)
{
	auto s = MakeChannelReqest(GetPeerChannel(), "exit-signal"sv, false);
	s.WriteString(signal_name);
	s.WriteBool(core_dumped);
	s.WriteString(error_message);
	s.WriteString("en"sv);
	connection.SendPacket(std::move(s));
}

void
Channel::SerializeOpenConfirmation([[maybe_unused]] Serializer &s) const
{
}

void
Channel::HandleRequest(std::string_view request_type,
		       std::span<const std::byte> type_specific,
		       bool want_reply)
{
	auto *request = new PendingRequest(*this, want_reply,
					   OnRequest(request_type, type_specific));
	pending_requests.push_back(*request);

	if (request->IsDone())
		SubmitRequestResponses();
	else
		request->Start();
}

void
Channel::SubmitRequestResponses() noexcept
{
	while (!pending_requests.empty()) {
		const auto &request = pending_requests.front();
		if (!request.IsDone())
			break;

		/* finished requests that want to reply have already
		   been removed from the list */
		assert(request.WantsReply());

		const bool success = request.WasSuccessful();
		pending_requests.pop_front_and_dispose(DeleteDisposer{});

		PacketSerializer s{
			success
			? MessageNumber::CHANNEL_SUCCESS
			: MessageNumber::CHANNEL_FAILURE,
		};

		s.WriteU32(peer_channel);
		connection.SendPacket(std::move(s));
	}
}

inline void
Channel::OnRequestDone(PendingRequest &request,
		       std::exception_ptr error) noexcept
{
	assert(request.IsDone());
	assert(!pending_requests.empty());

	if (error) {
		// TODO does this need to be connection-fatal?
		connection.CloseError(std::move(error));
		return;
	}

	if (!request.WantsReply()) {
		/* if the client doesn't want a reply, there's nothing
		   left to do and we can remove the request from any
		   position of the list */
		pending_requests.erase_and_dispose(pending_requests.iterator_to(request),
						   DeleteDisposer{});
	}

	SubmitRequestResponses();
}

void
Channel::OnWindowAdjust(std::size_t nbytes)
{
	send_window += nbytes;
}

void
Channel::OnData([[maybe_unused]] std::span<const std::byte> payload)
{
	ConsumeReceiveWindow(payload.size());
}

void
Channel::OnExtendedData([[maybe_unused]] ChannelExtendedDataType data_type,
			[[maybe_unused]] std::span<const std::byte> payload)
{
	ConsumeReceiveWindow(payload.size());
}

Co::EagerTask<bool>
Channel::OnRequest([[maybe_unused]] std::string_view request_type,
		   [[maybe_unused]] std::span<const std::byte> type_specific)
{
	co_return false;
}

} // namespace SSH
