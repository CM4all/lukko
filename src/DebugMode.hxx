// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

/**
 * If this is true, then Lukko runs as an unprivileged user.  This is
 * used for debugging it during development.
 */
#ifdef NDEBUG
static constexpr bool debug_mode = false;
#else
inline bool debug_mode;
#endif
