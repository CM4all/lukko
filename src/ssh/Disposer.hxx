// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

namespace SSH {

class Connection;

class ConnectionDisposer {
public:
	virtual void Dispose(Connection *connection) noexcept = 0;
};

} // namespace SSH
