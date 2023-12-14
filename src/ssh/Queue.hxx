// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "io/Iovec.hxx"
#include "util/AllocatedArray.hxx"

#include <cassert>
#include <cstddef>
#include <list>
#include <span>

/**
 * Manager for a queue of buffers scheduled for sending to a socket.
 */
class SendQueue {
	std::list<AllocatedArray<std::byte>> queue;

	/**
	 * How much of the first buffer was already sent?
	 */
	std::size_t consumed = 0;

public:
	bool empty() const noexcept {
		return queue.empty();
	}

	void Push(AllocatedArray<std::byte> &&src) noexcept {
		queue.emplace_back(std::move(src));
	}

	void Push(std::span<const std::byte> src) noexcept {
		queue.emplace_back(src);
	}

	std::span<const std::byte> front() const noexcept {
		assert(!empty());

		return queue.front();
	}

	/**
	 * Prepare a sendmsg() call by copying references to queued
	 * buffers to an #iovec array.
	 *
	 * @return the number of buffers added to #v
	 */
	std::size_t Prepare(std::span<struct iovec> v) noexcept {
		assert(!v.empty());

		std::size_t n = 0;

		std::size_t skip = consumed;
		for (std::span<const std::byte> i : queue) {
			assert(i.size() > skip);

			v[n++] = MakeIovec(i.subspan(skip));
			skip = 0;

			if (n >= v.size())
				break;
		}

		return n;
	}

	void Consume(std::size_t nbytes) noexcept {
		while (!queue.empty()) {
			const std::size_t remaining = queue.front().size() - consumed;

			if (nbytes < remaining) {
				consumed += nbytes;
				return;
			}

			nbytes -= remaining;
			consumed = 0;
			queue.pop_front();
		}

		assert(nbytes == 0);
	}
};
