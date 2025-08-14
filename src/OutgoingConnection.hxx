// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "ssh/Connection.hxx"

class SecretKey;

class OutgoingConnectionHandler {
public:
	virtual void OnOutgoingDestroy() noexcept = 0;
	virtual void OnOutgoingUserauthService() = 0;
	virtual void OnOutgoingUserauthSuccess() = 0;
	virtual void OnOutgoingUserauthFailure() = 0;
	virtual void OnOutgoingHandlePacket(SSH::MessageNumber msg,
					    std::span<const std::byte> payload) = 0;
	virtual void OnOutgoingDisconnecting(SSH::DisconnectReasonCode reason_code,
					     std::string_view msg) noexcept = 0;
	virtual void OnOutgoingDisconnected(SSH::DisconnectReasonCode reason_code,
					    std::string_view msg) noexcept = 0;
};

class OutgoingConnection final
	: public SSH::Connection
{
	OutgoingConnectionHandler &handler;

	enum class State : uint_least8_t {
		INIT,
		SERVICE_REQUEST_SSH_USERAUTH,
		SERVICE_SSH_USERAUTH,
		USERAUTH_REQUEST,
		USERAUTH_SUCCESS,
	} state = State::INIT;

public:
	OutgoingConnection(EventLoop &event_loop, UniqueSocketDescriptor fd,
			   OutgoingConnectionHandler &_handler);
	~OutgoingConnection() noexcept;

	void SendUserauthRequestHostbased(std::string_view username,
					  const SecretKey &key,
					  std::string_view key_algorithm);

private:
	void HandleServiceAccept(std::span<const std::byte> payload);

protected:
	/* virtual methods from class SSH::Connection */
	void Destroy() noexcept override;
	void HandlePacket(SSH::MessageNumber msg,
			  std::span<const std::byte> payload) override;
	void OnEncrypted() override;
	void OnDisconnecting(SSH::DisconnectReasonCode reason_code,
			     std::string_view msg) noexcept override;
	void OnDisconnected(SSH::DisconnectReasonCode reason_code,
			    std::string_view msg) noexcept override;

	/* virtual methods from class BufferedSocketHandler */
	void OnBufferedError(std::exception_ptr e) noexcept override;
};
