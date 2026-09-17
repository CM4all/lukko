// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "BufferedChannel.hxx"

namespace SSH {

void
BufferedChannel::OnData(std::span<const std::byte> payload)
{
	assert(!eof_pending);
	assert(queue.empty() == (queue_bytes == 0));

	if (!queue.empty()) {
		queue.Push(payload);
		queue_bytes += payload.size();
		return;
	}

	const auto nbytes = OnBufferedData(payload);
	if (nbytes < payload.size()) {
		const auto rest = payload.subspan(nbytes);
		queue.Push(rest);
		queue_bytes += rest.size();
	}
}

void
BufferedChannel::OnEof()
{
	assert(!eof_pending);
	assert(queue.empty() == (queue_bytes == 0));

	if (queue.empty())
		OnBufferedEof();
	else
		eof_pending = true;
}

void
BufferedChannel::ReadBuffer()
{
	assert(queue.empty() == (queue_bytes == 0));

	while (!queue.empty()) {
		const auto payload = queue.Read();
		assert(payload.size() <= queue_bytes);

		const auto nbytes = OnBufferedData(payload);
		queue.Consume(nbytes);
		queue_bytes -= nbytes;

		if (nbytes < payload.size())
			return;
	}

	assert(queue_bytes == 0);

	if (eof_pending) {
		eof_pending = false;
		OnBufferedEof();
	}
}

} // namespace SSH
