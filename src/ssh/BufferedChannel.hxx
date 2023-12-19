// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Channel.hxx"
#include "memory/BufferQueue.hxx"

namespace SSH {

/**
 * A subclass of #Channel which buffers unconsumed #CHANNEL_DATA
 * payloads.
 */
class BufferedChannel : public Channel {
	BufferQueue queue;

	bool eof_pending = false;

public:
	using Channel::Channel;

	// virtual methods from class Channel
	void OnData(std::span<const std::byte> payload) final;
	void OnEof() final;

protected:
	/**
	 *
	 */
	void ReadBuffer();

	/**
	 * @return the number of bytes consumed; if this is less than
	 * the given payload size, then the transmission is paused and
	 * method is expected to call ReadBuffer() eventually to
	 * resume the transmission
	 */
	[[nodiscard]]
	virtual std::size_t OnBufferedData(std::span<const std::byte> payload) = 0;
	virtual void OnBufferedEof() = 0;
};

} // namespace SSH
