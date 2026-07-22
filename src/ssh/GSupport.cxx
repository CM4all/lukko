// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "GSupport.hxx"
#include "Connection.hxx"
#include "PacketSerializer.hxx"
#include "ParsePacket.hxx"
#include "co/InvokeTask.hxx"
#include "co/Task.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "util/DeleteDisposer.hxx"

#include <cassert>

namespace SSH {

class GlobalRequestSupport::PendingGlobalRequest : public IntrusiveListHook<> {
	GlobalRequestSupport &connection;

	Co::EagerInvokeTask invoke_task;

	const bool want_reply;

	bool success;

public:
	PendingGlobalRequest(GlobalRequestSupport &_connection, bool _want_reply,
			     Co::EagerTask<bool> &&_task)
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

	void OnCompletion(std::exception_ptr &&error) noexcept {
		if (error)
			success = false;

		connection.OnGlobalRequestDone(*this, std::move(error));
	}
};

GlobalRequestSupport::GlobalRequestSupport(Connection &_connection,
					   GlobalRequestHandler &_handler) noexcept
	:connection(_connection), handler(_handler)
{
	connection.AddHandler(*this);
}

GlobalRequestSupport::~GlobalRequestSupport() noexcept
{
	pending_global_requests.clear_and_dispose(DeleteDisposer{});
}

void
GlobalRequestSupport::SubmitGlobalRequestResponses() noexcept
{
	while (!pending_global_requests.empty()) {
		const auto &request = pending_global_requests.front();
		if (!request.IsDone())
			break;

		/* finished requests that want no reply have already
		   been removed from the list */
		assert(request.WantsReply());

		const bool success = request.WasSuccessful();
		pending_global_requests.pop_front_and_dispose(DeleteDisposer{});

		connection.SendPacket(PacketSerializer{success
				? MessageNumber::REQUEST_SUCCESS
				: MessageNumber::REQUEST_FAILURE});
	}
}

inline void
GlobalRequestSupport::OnGlobalRequestDone(PendingGlobalRequest &request,
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
	}

	SubmitGlobalRequestResponses();
}

bool
GlobalRequestSupport::OnGlobalRequestError(std::exception_ptr error) noexcept
{
	connection.CloseError(std::move(error));
	return false;
}

inline void
GlobalRequestSupport::HandleGlobalRequest(std::span<const std::byte> payload)
{
	const auto p = ParseGlobalRequest(payload);

	auto *request = new PendingGlobalRequest(*this, p.want_reply,
						 handler.HandleGlobalRequest(p.request_name,
									     p.request_specific_data));
	pending_global_requests.push_back(*request);

	if (request->IsDone())
		SubmitGlobalRequestResponses();
	else
		request->Start();
}

bool
GlobalRequestSupport::HandlePacket(MessageNumber msg,
				   std::span<const std::byte> payload)
{
	if (!connection.IsEncrypted() || !connection.IsAuthenticated())
		return false;

	switch (msg) {
	case MessageNumber::GLOBAL_REQUEST:
		HandleGlobalRequest(payload);
		return true;

	default:
		return false;
	}
}

void
GlobalRequestSupport::OnDisconnecting() noexcept
{
	/* cancel all pending requests so they don't try to do any I/O
	   while we're waiting for the DISCONNECT to be flushed */
	pending_global_requests.clear_and_dispose(DeleteDisposer{});
}

} // namespace SSH
