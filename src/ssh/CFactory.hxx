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
	virtual void SerializeOpen(Serializer &s) const = 0;
	virtual std::unique_ptr<Channel> CreateChannel(ChannelInit init) = 0;
	virtual void OnChannelOpenFailure(ChannelOpenFailureReasonCode code,
					  std::string_view description) noexcept = 0;
};

} // namespace SSH
