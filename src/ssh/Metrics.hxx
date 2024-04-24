// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <cstdint>

namespace SSH {

struct Metrics {
	uint_least64_t packets_received, packets_sent;
	uint_least64_t bytes_received, bytes_sent;
};

} // namespace SSH
