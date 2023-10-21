// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "KexState.hxx"
#include "event/net/BufferedSocket.hxx"
#include "util/AllocatedArray.hxx"

#include <cstdint>
#include <memory>
#include <span>
#include <string>

class Key;

namespace SSH {

class PacketSerializer;
class Cipher;

class Connection : BufferedSocketHandler
{
	const Key &host_key;

	BufferedSocket socket;

	DefaultFifoBuffer decrypted_input;

	/**
	 * If non-zero, then we're currently waiting for the payload
	 * of a packet to be received.
	 */
	std::size_t packet_length = 0;

	std::string client_version;

	AllocatedArray<std::byte> client_kexinit, server_kexinit;

	KexState kex_state;

	std::unique_ptr<Cipher> receive_cipher, send_cipher;

	uint_least64_t receive_seq = 0, send_seq = 0;

	bool version_exchanged = false;

protected:
	/**
	 * An exception class that sends DISCONNECT and deletes the
	 * connection.
	 */
	struct Disconnect {
		DisconnectReasonCode reason_code;
		std::string_view msg;
	};

public:
	Connection(EventLoop &event_loop, UniqueSocketDescriptor fd,
		   const Key &_host_key);
	~Connection() noexcept;

	auto &GetEventLoop() const noexcept {
		return socket.GetEventLoop();
	}

protected:
	virtual void Destroy() noexcept = 0;

	SocketDescriptor GetSocket() const noexcept {
		return socket.GetSocket();
	}

	void SendPacket(std::span<const std::byte> src);

public:
	void SendPacket(PacketSerializer &&s);

protected:
	void SendDisconnect(DisconnectReasonCode reason_code, std::string_view msg);
	void DoDisconnect(DisconnectReasonCode reason_code, std::string_view msg);

	void SendKexInit();
	void SendECDHKexInitReply(std::span<const std::byte> client_ephemeral_public_key);
	void SendNewKeys();

	void HandleKexInit(std::span<const std::byte> payload);
	void HandleNewKeys(std::span<const std::byte> payload);
	void HandleECDHKexInit(std::span<const std::byte> payload);

	virtual void HandlePacket(MessageNumber msg,
				  std::span<const std::byte> payload);

private:
	bool DecryptPacket();

	virtual void HandleRawPacket(std::span<const std::byte> payload);

protected:
	/* virtual methods from class BufferedSocketHandler */
	BufferedResult OnBufferedData() override;
	bool OnBufferedClosed() noexcept override;
	bool OnBufferedWrite() override;
	void OnBufferedError(std::exception_ptr e) noexcept override;
};

} // namespace SSH
