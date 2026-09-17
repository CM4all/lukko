// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

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

	/**
	 * The total size of all buffers in the #queue.
	 */
	std::size_t queue_bytes = 0;

	bool eof_pending = false;

protected:
	/**
	 * If positive, then this class sends #CHANNEL_WINDOW_ADJUST
	 * automatically whenever the remaining receive window plus
	 * the queue size gets below a certain mark.
	 */
	std::size_t max_receive_window = 0;

public:
	using Channel::Channel;

	// virtual methods from class Channel
	void OnData(std::span<const std::byte> payload) final;
	void OnEof() final;

private:
	/**
	 * Invoke SendWindowAdjust() if the remaining #receive_window
	 * plus #queue_bytes is smaller than half the
	 * #max_receive_window.
	 */
	void MaybeSendWindowAdjust() noexcept {
		if (max_receive_window == 0)
			return;

		const std::size_t fill = GetReceiveWindow() + queue_bytes;
		if (fill < max_receive_window / 2)
			SendWindowAdjust(max_receive_window - fill);
	}

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
