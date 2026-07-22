// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "UserAuthClient.hxx"
#include "co/MultiResume.hxx"
#include "co/Task.hxx"

namespace SSH {

/**
 * A #UserAuthClientHandler that can be awaited on by C++ coroutines.
 * This is glue code designed for unit tests.
 */
class AwaitableUserAuthClientHandler : public UserAuthClientHandler {
	Co::MultiResume resume;

	bool service_accepted = false;

	bool got_reply = false, success;

public:
	Co::Task<void> WaitServiceAccepted() noexcept {
		while (!service_accepted)
			co_await resume;
	}

	Co::Task<bool> WaitReply() noexcept {
		while (!got_reply)
			co_await resume;
		got_reply = false;
		co_return success;
	}

protected:
	void OnUserAuthService() override {
		assert(!service_accepted);
		service_accepted = true;
		resume.ResumeAll();
	}

	void OnUserAuthSuccess() override {
		assert(service_accepted);

		got_reply = true;
		success = true;
		resume.ResumeAll();
	}

	void OnUserAuthFailure() override {
		assert(service_accepted);

		got_reply = true;
		success = false;
		resume.ResumeAll();
	}
};

} // namespace SSH
