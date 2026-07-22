// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "util/IntrusiveList.hxx"

#include <cstddef>
#include <cstdint>
#include <exception> // for std::exception_ptr
#include <span>
#include <string_view>

namespace Co { template<typename T> class EagerTask; }

namespace SSH {

enum class ChannelExtendedDataType : uint32_t;
class Connection;
class ChannelSupport;
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
	ChannelSupport &parent;
	Connection &connection;

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
	/**
	 * @param _receive_window the initial receive window size;
	 * must be the same value that was passed to
	 * ChannelSupport::OpenChannel()
	 */
	Channel(ChannelSupport &_parent, ChannelInit init,
		std::size_t _receive_window) noexcept;

	virtual ~Channel() noexcept;

	Connection &GetConnection() noexcept {
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

	/**
	 * Send a #CHANNEL_WINDOW_ADJUST packet, extending the receive
	 * window by the specified number of bytes.  This also updates
	 * the #receive_window field which can be accessed using
	 * GetReceiveWindow() and ConsumeReceiveWindow().
	 *
	 * This method cannot fail because only enqueues the packet.
	 */
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
	/**
	 * Consume a portion of the channel receive window by
	 * subtracting from #receive_window, to allow more data to be
	 * received by the client.  Call this for data that was passed
	 * to OnData() or OnExtendedData() after the data has really
	 * been consumed.  These virtuel methods are allowed to
	 * consume the data asynchronously; therefore, this method may
	 * be called after these two methods have already returned.
	 *
	 * After calling this method, depending on the return value,
	 * it may be useful to call SendWindowAdjust().
	 *
	 * @return the remaining receive window size
	 */
	std::size_t ConsumeReceiveWindow(std::size_t nbytes) noexcept;

public:
	/**
	 * Gives the object a chance to append more data to the
	 * #CHANNEL_OPEN_CONFIRMATION payload.
	 */
	virtual void SerializeOpenConfirmation(Serializer &s) const;

	/**
	 * A #CHANNEL_WINDOW_ADJUST packet was received.  This
	 * implementation updates #send_window, which can be accessed
	 * using GetSendWindow().
	 *
	 * Overrides may decide to resume sending pending data using
	 * SendData() or SendExtendedData() (which will then decrease
	 * the #send_window).
	 */
	virtual void OnWindowAdjust(std::size_t nbytes);

	/**
	 * Data was received on the channel.  As soon as data was
	 * consumed, call ConsumeReceiveWindow().
	 */
	virtual void OnData(std::span<const std::byte> payload);

	/**
	 * Extended data was received on the channel (usually STDERR
	 * of a #SessionChannel).  As soon as data was consumed, call
	 * ConsumeReceiveWindow().
	 */
	virtual void OnExtendedData(ChannelExtendedDataType data_type,
				    std::span<const std::byte> payload);

	/**
	 * The channel has ended and there will be no more data.
	 */
	virtual void OnEof() {}

	/**
	 * A #CHANNEL_REQUEST message was received.
	 *
	 * @return a coroutine that handles the request; its return
	 * value will (optionally) generate a #CHANNEL_SUCCESS or
	 * a #CHANNEL_FAILURE packet
	 */
	[[nodiscard]]
	virtual Co::EagerTask<bool> OnRequest(std::string_view request_type,
					      std::span<const std::byte> type_specific);
	/**
	 * A #CHANNEL_SUCCESS message was received.
	 */
	virtual void OnRequestSuccess();

	/**
	 * A #CHANNEL_FAILURE message was received.
	 */
	virtual void OnRequestFailure();

	virtual void OnWriteBlocked() noexcept {}
	virtual void OnWriteUnblocked() noexcept {}
};

} // namespace SSH
