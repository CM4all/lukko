// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "BufferedChannel.hxx"

namespace SSH {

void
BufferedChannel::OnData(std::span<const std::byte> payload)
{
	assert(!eof_pending);

	if (!queue.empty()) {
		queue.Push(payload);
		return;
	}

	const auto nbytes = OnBufferedData(payload);
	if (nbytes < payload.size())
		queue.Push(payload.subspan(nbytes));
}

void
BufferedChannel::OnEof()
{
	assert(!eof_pending);

	if (queue.empty())
		OnBufferedEof();
	else
		eof_pending = true;
}

void
BufferedChannel::ReadBuffer()
{
	while (!queue.empty()) {
		const auto payload = queue.Read();
		const auto nbytes = OnBufferedData(payload);
		queue.Consume(nbytes);

		if (nbytes < payload.size())
			return;
	}

	if (eof_pending) {
		eof_pending = false;
		OnBufferedEof();
	}
}

} // namespace SSH
