// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "Handler.hxx"

class SecretKey;

namespace SSH {

class Connection;

class UserAuthClientHandler {
public:
	virtual void OnUserAuthService() = 0;
	virtual void OnUserAuthSuccess() = 0;
	virtual void OnUserAuthFailure() = 0;
};

class UserAuthClient final : ConnectionHandler {
	Connection &connection;

	UserAuthClientHandler &handler;

	enum class State : uint_least8_t {
		INIT,
		SERVICE_REQUEST_SSH_USERAUTH,
		SERVICE_SSH_USERAUTH,
		USERAUTH_REQUEST,
		USERAUTH_SUCCESS,
	} state = State::INIT;

public:
	UserAuthClient(Connection &_connection,
		       UserAuthClientHandler &_handler);
	~UserAuthClient() noexcept;

	void Start();

	void SendUserAuthRequestPublicKey(std::string_view username,
					  const SecretKey &key,
					  std::string_view key_algorithm);

	void SendUserAuthRequestHostbased(std::string_view username,
					  const SecretKey &key,
					  std::string_view key_algorithm,
					  std::string_view client_host_name,
					  std::string_view client_user_name);

private:
	void HandleServiceAccept(std::span<const std::byte> payload);

protected:
	/* virtual methods from class ConnectionHandler */
	bool HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload) override;
};

} // namespace SSH
