// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "IHandler.hxx"
#include "KexState.hxx"
#include "KexEnums.hxx"
#include "event/FarTimerEvent.hxx"
#include "event/net/BufferedSocket.hxx"
#include "util/AllocatedArray.hxx"
#include "util/IntrusiveList.hxx"

#include <cstdint>
#include <span>
#include <string>

class SecretKey;

namespace SSH {

struct Metrics;
class PacketSerializer;
class Input;
class Output;
class Kex;
class HostKeyChooser;
class HostKeyVerifier;
class ConnectionDisposer;
class ConnectionHandler;
enum class MessageNumber : uint8_t;
enum class DisconnectReasonCode : uint32_t;
enum class KexAlgorithm : uint_least8_t;

class Connection : BufferedSocketHandler, InputHandler
{
	static constexpr uint_least64_t KILO = 1024;
	static constexpr uint_least64_t MEGA = 1024 * KILO;
	static constexpr uint_least64_t GIGA = 1024 * MEGA;

	static constexpr uint_least64_t REKEY_BYTES = GIGA;
	static constexpr auto REKEY_INTERVAL = std::chrono::hours{1};

	ConnectionDisposer &disposer;

	const HostKeyChooser *const host_key_chooser = nullptr;
	const HostKeyVerifier *const host_key_verifier = nullptr;

	const SecretKey *host_key;
	std::string host_key_algorithm;

	BufferedSocket socket;

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

	FarTimerEvent rekey_timer;
	uint_least64_t encrypted_bytes_since_kex = 0;

	struct HandlerHookTraits;
	IntrusiveList<ConnectionHandler, HandlerHookTraits> handlers;

	Metrics *metrics = nullptr;

	const Role role;

	/**
	 * If true, then the connection is about to be closed, only
         * waiting for the DISCONNECT to be encrypted and sent.
	 */
	bool dead = false;

	bool version_exchanged = false;

	bool authenticated = false;

	/**
	 * Did the peer announce "ext-info-c" or "ext-info-s"?
	 */
	bool peer_wants_ext_info = false;

	/**
	 * Did the peer announce ""kex-strict-[cs]-v00@openssh.com"?
	 */
	bool peer_wants_strict_key_exchange;

	/**
	 * Remember whether the first packet was KEXINIT.  If not and
	 * then KEXINIT enables #peer_wants_strict_key_exchange, the
	 * connection will be terminated.
	 */
	bool first_packet_was_kexinit = true;

	/**
	 * RFC 4253 section 7.1: if the peer set
	 * "first_kex_packet_follows" and guessed the negotiated
	 * algorithm wrong, then the next packet must be ignored.
	 */
	bool ignore_next_kex_packet = false;

	/**
	 * Is writing currently blocked (because the kernel socket is
	 * full)?  This keeps track whether to call
	 * OnWriteUnblocked().
	 */
	bool write_blocked = false;

	struct {
		bool kexinit_sent = false;
		bool kexinit_received = false;
		bool newkeys_sent = false;
		bool newkeys_received = false;

		constexpr bool IsIdle() const noexcept {
			return !kexinit_sent && !kexinit_received &&
				!newkeys_sent && !newkeys_received;
		}

		constexpr bool IsComplete() const noexcept {
			return newkeys_sent && newkeys_received;
		}

		constexpr bool ResetIfComplete() noexcept {
			bool complete = IsComplete();
			if (complete)
				*this = {};
			return complete;
		}
	} kex_flags;

public:
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
	[[nodiscard]]
	Connection(EventLoop &event_loop, UniqueSocketDescriptor &&fd,
		   ConnectionDisposer &_disposer,
		   Role _role,
		   const HostKeyChooser *_host_key_chooser=nullptr,
		   const HostKeyVerifier *_host_key_verifier=nullptr);

	[[nodiscard]]
	Connection(EventLoop &event_loop, UniqueSocketDescriptor &&fd,
		   ConnectionDisposer &_disposer,
		   const HostKeyChooser &_host_key_chooser)
		:Connection(event_loop, std::move(fd), _disposer,
			    Role::SERVER, &_host_key_chooser) {}

	[[nodiscard]]
	Connection(EventLoop &event_loop, UniqueSocketDescriptor &&fd,
		   ConnectionDisposer &_disposer,
		   const HostKeyVerifier &_host_key_verifier)
		:Connection(event_loop, std::move(fd), _disposer,
			    Role::CLIENT, nullptr, &_host_key_verifier) {}


	~Connection() noexcept;

	auto &GetEventLoop() const noexcept {
		return socket.GetEventLoop();
	}

	void AddHandler(ConnectionHandler &handler) noexcept;

	void SetMetrics(Metrics &_metrics) noexcept {
		metrics = &_metrics;
	}

	/**
	 * Is this connection "dead", i.e. was DoDisconnect() called?
	 * In this state, the socket may still be connected while we
	 * are sending the encrypted #DISCONNECT message.  Once that
	 * is finished, Destroy() will be called.
	 *
	 * A dead object must not be used for any I/O.
	 */
	bool IsDead() const noexcept {
		return dead;
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

	std::span<const std::byte> GetSessionId() const noexcept {
		return kex_state.session_id;
	}

protected:
	SocketDescriptor GetSocket() const noexcept {
		return socket.GetSocket();
	}

	/**
	 * Mark this connection as "authenticated".
	 */
	void SetAuthenticated() noexcept;

	/**
	 * Add a serialized (but unencrypted) packet to the send
	 * queue.
	 *
	 * This method cannot fail.
	 */
	void SendPacket(std::span<const std::byte> src) noexcept;

public:
	void SendPacket(PacketSerializer &&s) noexcept;

	void SendPacket(MessageNumber msg, std::span<const std::byte> src);

protected:
	void DoDisconnect(DisconnectReasonCode reason_code, std::string_view msg) noexcept;

	void SendKexInit();
	void SendECDHKexInit();
	void SendECDHKexInitReply(std::span<const std::byte> client_ephemeral_public_key);
	void SendNewKeys();
	void SendExtInfo();

	[[noreturn]]
	void HandleDisconnect(std::span<const std::byte> payload);
	void HandleKexInit(std::span<const std::byte> payload);
	void HandleNewKeys(std::span<const std::byte> payload);
	void HandleECDHKexInit(std::span<const std::byte> payload);
	void HandleECDHKexInitReply(std::span<const std::byte> payload);

	/**
	 * Called after key exchange (KEX) has completed successfully
	 * and a cipher has been established for both directions.
	 */
	virtual void OnEncrypted() {}

	/**
	 * The (kernel) socket buffer is full and no more outgoing packets
	 * should be submitted to SendPacket().
	 *
	 * Writing (of regular non-KEX packets) can also be blocked by
	 * rekeying (after sending KEXINIT on a connection that is
	 * already encrypted).
	 */
	void OnWriteBlocked() noexcept;

	/**
	 * The (kernel) socket buffer is no longer full and
	 * SendPacket() may be called (but not from inside this
	 * method; this method shall only schedule events to produce
	 * more data).
	 */
	void OnWriteUnblocked() noexcept;

	/**
	 * Called right before sending a DISCONNECT packet to the
	 * peer.  This may be used for logging (but not for I/O or for
	 * actually disconnecting).
	 */
	virtual void OnDisconnecting(DisconnectReasonCode reason_code,
				     std::string_view msg) noexcept;

	/**
	 * Called before handling a DISCONNECT packet received from
	 * the peer.  This may be used for logging (but not for I/O or
	 * for actually disconnecting).
	 */
	virtual void OnDisconnected(DisconnectReasonCode reason_code,
				    std::string_view msg) noexcept;

private:
	[[gnu::pure]]
	bool IsRekeying() const noexcept;

	void InitiateRekey();
	void OnRekeyTimer() noexcept;

	void HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload);

	void HandleRawPacket(std::span<const std::byte> payload);

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
