// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <string_view>

namespace Co { template<typename> class Task; }
struct TranslateResponse;
class AllocatorPtr;
class EventLoop;

Co::Task<TranslateResponse>
TranslateLogin(EventLoop &event_loop,
	       AllocatorPtr alloc, const char *socket_path,
	       std::string_view service, std::string_view listener_tag,
	       std::string_view user, std::string_view password,
	       bool probe);
