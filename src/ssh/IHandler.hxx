// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <exception>

namespace SSH {

/**
 * Handler for #Input.
 */
class InputHandler {
public:
	/**
	 * @return false if the #Input was destroyed
	 */
	virtual bool OnInputReady() noexcept = 0;
};

} // namespace SSH
