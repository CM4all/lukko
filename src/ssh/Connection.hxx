// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "IHandler.hxx"
#include "KexState.hxx"
#include "event/net/BufferedSocket.hxx"
#include "util/AllocatedArray.hxx"

#include <cstdint>
#include <span>
#include <string>

class SecretKey;

namespace SSH {

class PacketSerializer;
class Input;
class Output;
class Kex;
enum class MessageNumber : uint8_t;
enum class DisconnectReasonCode : uint32_t;
enum class KexAlgorithm : uint_least8_t;

class Connection : BufferedSocketHandler, InputHandler
{
	const SecretKey *host_key;
	std::string host_key_algorithm;

	BufferedSocket socket;

	/**
	 * If non-zero, then we're currently waiting for the payload
	 * of a packet to be received.
	 */
	std::size_t packet_length = 0;

	std::string peer_version;

	AllocatedArray<std::byte> peer_kexinit, my_kexinit;

	std::string encryption_algorithms_client_to_server,
		encryption_algorithms_server_to_client,
		mac_algorithms_client_to_server,
		mac_algorithms_server_to_client;

	KexState kex_state;

	std::unique_ptr<Kex> kex_algorithm;

	Input &input;
	Output &output;

	const Role role;

	bool version_exchanged = false;

	bool authenticated = false;

	/**
	 * Did the peer announce "kex-info-c" or "kex-info-s"?
	 */
	bool peer_wants_ext_info = false;

protected:
	/**
	 * An exception class that sends DISCONNECT and deletes the
	 * connection.
	 */
	struct Disconnect {
		DisconnectReasonCode reason_code;
		std::string_view msg;
	};

	/**
	 * An exception class that, when caught, assumes that this
	 * #Connection instance was destroyed.
	 */
	struct Destroyed {};

public:
	Connection(EventLoop &event_loop, UniqueSocketDescriptor fd,
		   Role _role);
	~Connection() noexcept;

	auto &GetEventLoop() const noexcept {
		return socket.GetEventLoop();
	}

	[[gnu::pure]]
	bool IsEncrypted() const noexcept;

	bool IsAuthenticated() const noexcept {
		return authenticated;
	}

	/**
	 * Close this connection due to an error.
	 */
	void CloseError(std::exception_ptr e) noexcept {
		OnBufferedError(std::move(e));
	}

protected:
	virtual void Destroy() noexcept = 0;

	SocketDescriptor GetSocket() const noexcept {
		return socket.GetSocket();
	}

	std::span<const std::byte> GetSessionId() const noexcept {
		return kex_state.session_id;
	}

	void SetAuthenticated() noexcept {
		assert(IsEncrypted());
		assert(!authenticated);

		authenticated = true;
	}

	void SendPacket(std::span<const std::byte> src);

public:
	/**
	 * Throws on error.
	 */
	void SendPacket(PacketSerializer &&s);

protected:
	void SendDisconnect(DisconnectReasonCode reason_code, std::string_view msg);
	void DoDisconnect(DisconnectReasonCode reason_code, std::string_view msg) noexcept;

	void SendKexInit();
	void SendECDHKexInit();
	void SendECDHKexInitReply(std::span<const std::byte> client_ephemeral_public_key);
	void SendNewKeys();
	void SendExtInfo();

	void HandleKexInit(std::span<const std::byte> payload);
	void HandleNewKeys(std::span<const std::byte> payload);
	void HandleECDHKexInit(std::span<const std::byte> payload);
	void HandleECDHKexInitReply(std::span<const std::byte> payload);

	virtual void HandlePacket(MessageNumber msg,
				  std::span<const std::byte> payload);

	[[gnu::pure]]
	virtual std::string_view GetServerHostKeyAlgorithms() const noexcept;

	[[gnu::pure]]
	virtual std::pair<const SecretKey *, std::string_view> ChooseHostKey([[maybe_unused]] std::string_view algorithms) const noexcept {
		return {nullptr, {}};
	}

	/**
	 * Called after key exchange (KEX) has completed successfully
	 * and a cipher has been established for both directions.
	 */
	virtual void OnEncrypted() {}

	/**
	 * The (kernel) socket buffer is full and no more outgoing packets
	 * should be submitted to SendPacket().
	 */
	virtual void OnWriteBlocked() noexcept {}

	/**
	 * The (kernel) socket buffer is no longer full and
	 * SendPacket() may be called (but not from inside this
	 * method; this method shall only schedule events to produce
	 * more data).
	 */
	virtual void OnWriteUnblocked() noexcept {}

private:
	const auto &GetServerKexinit() const {
		return role == Role::SERVER
			? my_kexinit
			: peer_kexinit;
	}

	bool IsPastKexInit() const noexcept {
		return GetServerKexinit() != nullptr;
	}

	virtual void HandleRawPacket(std::span<const std::byte> payload);

protected:
	/* virtual methods from class BufferedSocketHandler */
	BufferedResult OnBufferedData() override;
	bool OnBufferedClosed() noexcept override;
	bool OnBufferedWrite() override;
	void OnBufferedError(std::exception_ptr e) noexcept override;

	/* virtual methods from class InputHandler */
	bool OnInputReady() noexcept final;
};

} // namespace SSH
