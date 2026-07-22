// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "ssh/Protocol.hxx"

constexpr bool
ShouldProxy(SSH::MessageNumber msg) noexcept
{
	using enum SSH::MessageNumber;

	switch (msg) {
	case GLOBAL_REQUEST:
	case REQUEST_SUCCESS:
	case REQUEST_FAILURE:
	case CHANNEL_OPEN:
	case CHANNEL_OPEN_CONFIRMATION:
	case CHANNEL_OPEN_FAILURE:
	case CHANNEL_WINDOW_ADJUST:
	case CHANNEL_DATA:
	case CHANNEL_EXTENDED_DATA:
	case CHANNEL_EOF:
	case CHANNEL_CLOSE:
	case CHANNEL_REQUEST:
	case CHANNEL_SUCCESS:
	case CHANNEL_FAILURE:
		/* proxy these messages between real client and real
		   server */
		return true;

	default:
		/* don't proxy all other messages; they may be
		   hop-by-hop messages such as KEX */
		return false;
	}
}
