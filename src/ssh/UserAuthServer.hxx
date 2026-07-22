// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "Handler.hxx"
#include "co/InvokeTask.hxx"

#include <exception>

template<typename T> class AllocatedArray;

namespace SSH {

class Connection;

class UserAuthServerHandler {
public:
	virtual void OnUnsupportedService() noexcept {}

	[[nodiscard]]
	virtual Co::EagerInvokeTask OnUserAuthRequest(AllocatedArray<std::byte> payload) = 0;

	virtual void OnUserAuthCompletion() noexcept {}
};

class UserAuthServer final : ConnectionHandler {
	Connection &connection;

	UserAuthServerHandler &handler;

	/**
	 * If this is set, then the connection is currently occupied
	 * with an asynchronous operation (e.g. lookup in the user
	 * database).  Until it finishes, most incoming packets will
	 * cause the connection to be closed.
	 */
	Co::EagerInvokeTask occupied_task;

	bool have_service_userauth = false;

public:
	UserAuthServer(Connection &_connection,
		       UserAuthServerHandler &_handler) noexcept;
	~UserAuthServer() noexcept;

private:
	bool IsOccupied() const noexcept {
		return occupied_task;
	}

	void HandleServiceRequest(std::span<const std::byte> payload);
	void OnUserAuthCompletion(std::exception_ptr &&error) noexcept;
	void HandleUserauthRequest(std::span<const std::byte> payload);

protected:
	/* virtual methods from class ConnectionHandler */
	bool HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload) override;
};

} // namespace SSH
