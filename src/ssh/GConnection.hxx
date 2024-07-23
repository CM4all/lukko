// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Connection.hxx"
#include "util/IntrusiveList.hxx"

namespace Co { template<typename T> class EagerTask; }

namespace SSH {

/**
 * Add GLOBAL_REQUEST suport to to class #Connection.  Override method
 * HandleGlobalRequest().
 */
class GConnection : public Connection
{
	class PendingGlobalRequest;

	/**
	 * The list of GLOBAL_REQUESTs that are either still running
	 * asynchronously or have finished but their replies cannot
	 * yet be delivered because they need to be in-order and an
	 * older request hasn't yet finished (see RFC 4254 section 4).
	 */
	IntrusiveList<PendingGlobalRequest> pending_global_requests;

public:
	GConnection(EventLoop &event_loop, UniqueSocketDescriptor fd,
		    Role _role);
	~GConnection() noexcept;

private:
	void SubmitGlobalRequestResponses() noexcept;
	void OnGlobalRequestDone(PendingGlobalRequest &request,
				 std::exception_ptr error) noexcept;

	void HandleGlobalRequest(std::span<const std::byte> payload);

protected:
	/**
	 * @return true on success (sends REQUEST_SUCCESS), false on
	 * error (sends REQUEST_FAILURE)
	 */
	virtual Co::EagerTask<bool> HandleGlobalRequest(std::string_view request_name,
							std::span<const std::byte> request_specific_data);

	/**
	 * @return false if the connection was destroyed
	 */
	virtual bool OnGlobalRequestError(std::exception_ptr error) noexcept;

	/* virtual methods from class SSH::Connection */
	void HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload) override;
	void OnDisconnecting(DisconnectReasonCode reason_code,
			     std::string_view msg) noexcept override;
};

} // namespace SSH
