// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "ssh/Disposer.hxx"
#include "ssh/UserAuthClient.hxx"
#include "ssh/Connection.hxx"
#include "ssh/SimpleHostKeyVerifier.hxx"

#include <memory>

class SecretKey;
class PublicKeySet;

class OutgoingConnectionHandler : public SSH::ConnectionDisposer {
public:
	/**
	 * An error has occurred on the connection and it should be
	 * closed.  This will be called instead of
	 * OnOutgoingDestroy().
	 */
	virtual void OnOutgoingError(std::exception_ptr &&error) noexcept = 0;

	virtual void OnOutgoingUserauthService() = 0;
	virtual void OnOutgoingUserauthSuccess() = 0;
	virtual void OnOutgoingUserauthFailure() = 0;
	virtual void OnOutgoingDisconnecting(SSH::DisconnectReasonCode reason_code,
					     std::string_view msg) noexcept = 0;
	virtual void OnOutgoingDisconnected(SSH::DisconnectReasonCode reason_code,
					    std::string_view msg) noexcept = 0;
};

class OutgoingConnection final
	: public SSH::Connection, SSH::UserAuthClientHandler
{
	const SSH::SimpleHostKeyVerifier server_host_key_verifier;

	OutgoingConnectionHandler &handler;

	std::unique_ptr<SSH::UserAuthClient> user_auth;

public:
	OutgoingConnection(EventLoop &event_loop, const PublicKeySet &_server_host_keys,
			   UniqueSocketDescriptor &&fd,
			   OutgoingConnectionHandler &_handler);
	~OutgoingConnection() noexcept;

	void SendUserauthRequestHostbased(std::string_view username,
					  const SecretKey &key,
					  std::string_view key_algorithm,
					  std::string_view client_host_name,
					  std::string_view client_user_name);

private:
	void HandleServiceAccept(std::span<const std::byte> payload);

protected:
	/* virtual methods from class SSH::UserAuthClientHandler */
	void OnUserAuthService() override;
	void OnUserAuthSuccess() override;
	void OnUserAuthFailure() override;

	/* virtual methods from class SSH::Connection */
	void OnEncrypted() override;
	void OnDisconnecting(SSH::DisconnectReasonCode reason_code,
			     std::string_view msg) noexcept override;
	void OnDisconnected(SSH::DisconnectReasonCode reason_code,
			    std::string_view msg) noexcept override;

	/* virtual methods from class BufferedSocketHandler */
	void OnBufferedError(std::exception_ptr e) noexcept override;
};
