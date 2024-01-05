// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "GConnection.hxx"
#include "PacketSerializer.hxx"
#include "ParsePacket.hxx"
#include "co/InvokeTask.hxx"
#include "co/Task.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "util/DeleteDisposer.hxx"

#include <cassert>

namespace SSH {

class GConnection::PendingGlobalRequest : public IntrusiveListHook<> {
	GConnection &connection;

	Co::EagerInvokeTask invoke_task;

	const bool want_reply;

	bool success;

public:
	PendingGlobalRequest(GConnection &_connection, bool _want_reply,
			     Co::EagerTask<bool> &&_task) noexcept
		:connection(_connection),
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

	void OnCompletion(std::exception_ptr error) noexcept {
		if (error)
			success = false;

		connection.OnGlobalRequestDone(*this, std::move(error));
	}
};

GConnection::GConnection(EventLoop &event_loop, UniqueSocketDescriptor fd,
			 Role _role)
	:Connection(event_loop, std::move(fd), _role) {}

GConnection::~GConnection() noexcept
{
	pending_global_requests.clear_and_dispose(DeleteDisposer{});
}

void
GConnection::SubmitGlobalRequestResponses()
{
	while (!pending_global_requests.empty()) {
		const auto &request = pending_global_requests.front();
		if (!request.IsDone())
			break;

		/* finished requests that want to reply have already
		   been removed from the list */
		assert(request.WantsReply());

		const bool success = request.WasSuccessful();
		pending_global_requests.pop_front_and_dispose(DeleteDisposer{});

		SendPacket(PacketSerializer{success
				? MessageNumber::REQUEST_SUCCESS
				: MessageNumber::REQUEST_FAILURE});
	}
}

inline void
GConnection::OnGlobalRequestDone(PendingGlobalRequest &request,
				 std::exception_ptr error) noexcept
{
	assert(request.IsDone());
	assert(!pending_global_requests.empty());

	if (error && !OnGlobalRequestError(std::move(error)))
		return;

	if (!request.WantsReply()) {
		/* if the client doesn't want a reply, there's nothing
		  left to do and we can remove the request from any
		  position of the list */
		pending_global_requests.erase_and_dispose(pending_global_requests.iterator_to(request),
							  DeleteDisposer{});
		return;
	}

	if (&pending_global_requests.front() == &request) {
		try {
			SubmitGlobalRequestResponses();
		} catch (...) {
			OnBufferedError(std::current_exception());
		}
	}
}

Co::EagerTask<bool>
GConnection::HandleGlobalRequest([[maybe_unused]] std::string_view request_name,
				 [[maybe_unused]] std::span<const std::byte> request_specific_data)
{
	co_return false;
}

bool
GConnection::OnGlobalRequestError(std::exception_ptr error) noexcept
{
	OnBufferedError(std::move(error));
	return false;
}

inline void
GConnection::HandleGlobalRequest(std::span<const std::byte> payload)
{
	const auto p = ParseGlobalRequest(payload);

	auto *request = new PendingGlobalRequest(*this, p.want_reply,
						 HandleGlobalRequest(p.request_name,
								     p.request_specific_data));
	pending_global_requests.push_back(*request);

	if (request->IsDone())
		SubmitGlobalRequestResponses();
	else
		request->Start();
}

void
GConnection::HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload)
{
	if (!IsEncrypted() || !IsAuthenticated())
		return Connection::HandlePacket(msg, payload);

	switch (msg) {
	case MessageNumber::GLOBAL_REQUEST:
		HandleGlobalRequest(payload);
		break;

	default:
		Connection::HandlePacket(msg, payload);
	}
}

} // namespace SSH
