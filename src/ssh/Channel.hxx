// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "util/IntrusiveList.hxx"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace Co { template<typename T> class EagerTask; }

namespace SSH {

enum class ChannelExtendedDataType : uint32_t;
class CConnection;
class Serializer;

/**
 * Structure passed to the #Channel constructor to reduce the
 * boilerplate code for derived classes.
 */
struct ChannelInit {
	uint_least32_t local_channel, peer_channel;

	std::size_t send_window;
};

class Channel {
	CConnection &connection;

	const uint_least32_t local_channel, peer_channel;

	/**
	 * How much data is the peer allowed to send?  Implementations
	 * should call SendWindowAdjust() to increase it.
	 */
	std::size_t receive_window;

	/**
	 * How much data are we allowed to send?  If this reaches
	 * zero, then we need to wait for CHANNEL_WINDOW_ADJUST.
	 */
	std::size_t send_window;

	class PendingRequest;

	/**
	 * The list of requests that are still running asynchronously
	 * or have finished but their replies cannot yet be delivered
	 * because they need to be in-order and an older request
	 * hasn't yet finished.
	 */
	IntrusiveList<PendingRequest> pending_requests;

public:
	Channel(CConnection &_connection, ChannelInit init,
		std::size_t _receive_window) noexcept;

	virtual ~Channel() noexcept;

	CConnection &GetConnection() noexcept {
		return connection;
	}

	uint_least32_t GetLocalChannel() const noexcept {
		return local_channel;
	}

	uint_least32_t GetPeerChannel() const noexcept {
		return peer_channel;
	}

	std::size_t GetReceiveWindow() const noexcept {
		return receive_window;
	}

	std::size_t GetSendWindow() const noexcept {
		return send_window;
	}

	void Close() noexcept;

	void SendWindowAdjust(uint_least32_t nbytes) noexcept;
	void SendData(std::span<const std::byte> src);
	void SendExtendedData(ChannelExtendedDataType data_type,
			      std::span<const std::byte> src);
	void SendStderr(std::span<const std::byte> src);
	void SendEof() noexcept;
	void SendExitStatus(uint_least32_t exit_status) noexcept;
	void SendExitSignal(std::string_view signal_name, bool core_dumped,
			    std::string_view error_message);

	void HandleRequest(std::string_view request_type,
			   std::span<const std::byte> type_specific,
			   bool want_reply);

private:
	void SubmitRequestResponses() noexcept;

	/**
	 * Called by PendingRequest after the coroutine completes.
	 */
	void OnRequestDone(PendingRequest &request,
			   std::exception_ptr error) noexcept;

protected:
	std::size_t ConsumeReceiveWindow(std::size_t nbytes) noexcept;

public:
	virtual void SerializeOpenConfirmation(Serializer &s) const;
	virtual void OnWindowAdjust(std::size_t nbytes);
	virtual void OnData(std::span<const std::byte> payload);
	virtual void OnExtendedData(ChannelExtendedDataType data_type,
				    std::span<const std::byte> payload);
	virtual void OnEof() {}

	[[nodiscard]]
	virtual Co::EagerTask<bool> OnRequest(std::string_view request_type,
					      std::span<const std::byte> type_specific);

	virtual void OnWriteBlocked() noexcept {}
	virtual void OnWriteUnblocked() noexcept {}
};

} // namespace SSH
