// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Connection.hxx"

namespace SSH {

/**
 * Add GLOBAL_REQUEST suport to to class #Connection.  Override method
 * HandleGlobalRequest().
 */
class GConnection : public Connection
{
public:
	using Connection::Connection;

private:
	void HandleGlobalRequest(std::span<const std::byte> payload);

protected:
	/**
	 * @return true on success (sends REQUEST_SUCCESS), false on
	 * error (sends REQUEST_FAILURE)
	 */
	virtual bool HandleGlobalRequest(std::string_view request_name,
					 std::span<const std::byte> request_specific_data);

	/* virtual methods from class SSH::Connection */
	void HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload) override;
};

} // namespace SSH
