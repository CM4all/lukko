// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Connection.hxx"

#include <array>
#include <cstdint>
#include <memory>

class CancellablePointer;

namespace SSH {

enum class ChannelOpenFailureReasonCode : uint32_t;
struct ChannelInit;
class Channel;

/**
 * Add SSH channel support to class #Connection.  Override method
 * OpenChannel().
 */
class CConnection : public Connection
{
	static constexpr uint_least32_t MAXIMUM_PACKET_SIZE = 32768;

	std::array<Channel *, 64> channels{};

public:
	using Connection::Connection;

	~CConnection() noexcept;

	/**
	 * Throws on error.
	 */
	void CloseChannel(Channel &channel);

	/**
	 * Exception class to be thrown from inside OpenChannel(),
	 * caught by HandleChannelOpen().
	 */
	struct ChannelOpenFailure {
		ChannelOpenFailureReasonCode reason_code;
		std::string_view description;
	};

	/**
	 * If SendPacket() fails, then this method destroys the
	 * #CConnection.
	 */
	void AsyncChannelOpenSuccess(Channel &channel) noexcept;

	/**
	 * If SendPacket() fails, then this method destroys the
	 * #CConnection.
	 */
	void AsyncChannelOpenFailure(ChannelInit init,
				     ChannelOpenFailureReasonCode reason_code,
				     std::string_view description) noexcept;

private:
	/**
	 * Find a free channel number.  Throws #ChannelOpenFailure on
	 * error.
	 */
	uint_least32_t AllocateChannelIndex();

	/**
	 * Look up a #Channel instance by its local channel number.
	 *
	 * Throws #Disconnect if the channel does not exist.
	 */
	Channel &GetChannel(uint_least32_t local_channel);

	void HandleChannelOpen(std::string_view channel_type,
			       uint_least32_t peer_channel,
			       uint_least32_t initial_window_size,
			       std::span<const std::byte> payload);
	void HandleChannelOpen(std::span<const std::byte> payload);
	void HandleChannelWindowAdjust(std::span<const std::byte> payload);
	void HandleChannelData(std::span<const std::byte> payload);
	void HandleChannelExtendedData(std::span<const std::byte> payload);
	void HandleChannelEof(std::span<const std::byte> payload);
	void HandleChannelClose(std::span<const std::byte> payload);
	void HandleChannelRequest(std::span<const std::byte> payload);

protected:
	/**
	 * The peer has requested opening a channel.
	 *
	 * Throws #ChannelOpenFailure on error
	 *
	 * @param channel_type the type of the channel
	 * @param init opaque initialization data for the #Channel constructor
	 * @param payload the remaining payload specific to this channel type
	 * @param cancel_ptr a cancellation hook (for channels that
	 * are created asynchronously)
	 * @return the new channel (nullptr if creating the channel
	 * is asynchronous; upon completion, call
	 * AsyncChannelOpenSuccess() or AsyncChannelOpenFailure())
	 */
	virtual std::unique_ptr<Channel> OpenChannel(std::string_view channel_type,
						     ChannelInit init,
						     std::span<const std::byte> payload,
						     CancellablePointer &cancel_ptr);

	/* virtual methods from class SSH::Connection */
	void HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload) override;
	void OnWriteBlocked() noexcept override;
	void OnWriteUnblocked() noexcept override;
};

} // namespace SSH
