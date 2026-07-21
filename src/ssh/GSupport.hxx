// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "Handler.hxx"
#include "util/IntrusiveList.hxx"

#include <exception>

namespace Co { template<typename T> class EagerTask; }

namespace SSH {

class Connection;

/**
 * Handler class for class #GlobalRequestSupport.
 */
class GlobalRequestHandler {
public:
	/**
	 * @return true on success (sends REQUEST_SUCCESS), false on
	 * error (sends REQUEST_FAILURE)
	 */
	virtual Co::EagerTask<bool> HandleGlobalRequest(std::string_view request_name,
							std::span<const std::byte> request_specific_data) = 0;
};

/**
 * Add GLOBAL_REQUEST support to to class #Connection.  Override method
 * HandleGlobalRequest().
 */
class GlobalRequestSupport final : ConnectionHandler
{
	class PendingGlobalRequest;

	Connection &connection;
	GlobalRequestHandler &handler;

	/**
	 * The list of GLOBAL_REQUESTs that are either still running
	 * asynchronously or have finished but their replies cannot
	 * yet be delivered because they need to be in-order and an
	 * older request hasn't yet finished (see RFC 4254 section 4).
	 */
	IntrusiveList<PendingGlobalRequest> pending_global_requests;

public:
	GlobalRequestSupport(Connection &_connection, GlobalRequestHandler &_handler) noexcept;
	~GlobalRequestSupport() noexcept;

private:
	void SubmitGlobalRequestResponses() noexcept;
	void OnGlobalRequestDone(PendingGlobalRequest &request,
				 std::exception_ptr error) noexcept;

	void HandleGlobalRequest(std::span<const std::byte> payload);

protected:
	/**
	 * @return false if the connection was destroyed
	 */
	bool OnGlobalRequestError(std::exception_ptr error) noexcept;

	/* virtual methods from class SSH::ConnectionHandler */
	bool HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload) override;
	void OnDisconnecting(DisconnectReasonCode reason_code,
			     std::string_view msg) noexcept override;
};

} // namespace SSH
