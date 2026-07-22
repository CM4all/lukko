// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "Connection.hxx"
#include "event/DeferEvent.hxx"
#include "co/MultiResume.hxx"
#include "co/Task.hxx"

namespace SSH {

/**
 * A #Connection that can be awaited on by C++ coroutines.  This is
 * glue code designed for unit tests.
 */
class AwaitableConnection : public SSH::Connection {
	DeferEvent defer_resume{GetEventLoop(), BIND_THIS_METHOD(Resume)};

	Co::MultiResume resume;

	bool disconnected = false;

public:
	using SSH::Connection::Connection;

	~AwaitableConnection() noexcept {
		disconnected = true;
		resume.ResumeAll();
	}

	Co::Task<void> WaitEncrypted() {
		while (!IsEncrypted() && !disconnected)
			co_await resume;

		if (disconnected)
			throw std::runtime_error{"Disconnected"};
	}

	Co::Task<void> WaitDisconnect() noexcept {
		while (!disconnected)
			co_await resume;
	}

private:
	void Resume() noexcept {
		resume.ResumeAll();
	}

	/* virtual methods from class SSH::Connection */
	void OnEncrypted() override {
		defer_resume.Schedule();
	}
};

} // namespace SSH
