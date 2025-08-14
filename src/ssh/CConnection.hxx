// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "GConnection.hxx"

#include <array>
#include <cstdint>
#include <memory>

class CancellablePointer;

namespace SSH {

enum class ChannelOpenFailureReasonCode : uint32_t;
struct ChannelInit;
class Channel;
class RequestedChannel;
class Serializer;

/**
 * A factory for a channel requested from this host to the peer.  An
 * instance is created by the OpenChannel() caller.
 */
class ChannelFactory {
public:
	virtual void SerializeOpen(Serializer &s) const = 0;
	virtual std::unique_ptr<Channel> CreateChannel(ChannelInit init) = 0;
	virtual void OnChannelOpenFailure(ChannelOpenFailureReasonCode code,
					  std::string_view description) noexcept = 0;
};

/**
 * Add SSH channel support to class #Connection.  Override method
 * CreateChannel().
 */
class CConnection : public GConnection
{
	static constexpr uint_least32_t MAXIMUM_PACKET_SIZE = 32768;

	std::array<Channel *, 64> channels{};

public:
	using GConnection::GConnection;

	~CConnection() noexcept;

	/**
	 * Send a CHANNEL_OPEN to the peer.  As soon as the peer
	 * confirms, the #ChannelFactory is asked to create the
	 * #Channel instance; if the peer instead rejects the channel,
	 * ChannelFactory::OnChannelOpenFailure() is called.
	 *
	 * Throws on error.
	 *
	 * @param factory the factory that will create the #Channel
	 * instance or receives a failure callback; its lifetime is
	 * managed by the caller
	 */
	void OpenChannel(std::string_view channel_type,
			 uint_least32_t initial_window_size,
			 ChannelFactory &factory,
			 CancellablePointer &cancel_ptr);

	void CloseChannel(Channel &channel) noexcept;

	/**
	 * Exception class to be thrown from inside CreateChannel(),
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

	RequestedChannel &PopRequestedChannel(uint_least32_t local_channel);

	void HandleChannelOpen(std::string_view channel_type,
			       uint_least32_t peer_channel,
			       uint_least32_t initial_window_size,
			       std::span<const std::byte> payload);
	void HandleChannelOpen(std::span<const std::byte> payload);
	void HandleChannelOpenConfirmation(std::span<const std::byte> payload);
	void HandleChannelOpenFailure(std::span<const std::byte> payload);
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
	virtual std::unique_ptr<Channel> CreateChannel(std::string_view channel_type,
						       ChannelInit init,
						       std::span<const std::byte> payload,
						       CancellablePointer &cancel_ptr);

	/* virtual methods from class SSH::Connection */
	void HandlePacket(MessageNumber msg,
			  std::span<const std::byte> payload) override;
	void OnWriteBlocked() noexcept override;
	void OnWriteUnblocked() noexcept override;
	void OnDisconnecting(DisconnectReasonCode reason_code,
			     std::string_view msg) noexcept override;
};

} // namespace SSH
