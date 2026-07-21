// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>

namespace SSH {

enum class ChannelOpenFailureReasonCode : uint32_t;
struct ChannelInit;
class Channel;
class Serializer;

/**
 * A factory for a channel requested from this host to the peer.  An
 * instance is created by the ChannelSupport::OpenChannel() caller.
 */
class ChannelFactory {
public:
	/**
	 * Serialize the CHANNEL_OPEN payload.
	 */
	virtual void SerializeOpen(Serializer &s) const = 0;

	/**
	 * The peer has agreed to open the channel.  This method
	 * creates the #Channel instance for the new channel.
	 *
	 * Throws on error.
	 *
	 * After returning, the #ChannelFactory is no longer used by
	 * the #ChannelSupport object.
	 */
	virtual std::unique_ptr<Channel> CreateChannel(ChannelInit init) = 0;

	/**
	 * The peer has refused to open the channel.
	 *
	 * After returning, the #ChannelFactory is no longer used by
	 * the #ChannelSupport object.
	 */
	virtual void OnChannelOpenFailure(ChannelOpenFailureReasonCode code,
					  std::string_view description) noexcept = 0;

	/**
	 * Creating the channel has been canceled by the
	 * #ChannelSupport object, e.g. because the SSH connection is
	 * being closed.
	 *
	 * After returning, the #ChannelFactory is no longer used by
	 * the #ChannelSupport object.
	 */
	virtual void OnChannelCancel() noexcept = 0;
};

} // namespace SSH
