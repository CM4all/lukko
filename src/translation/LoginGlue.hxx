// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <string_view>

struct TranslateResponse;
class AllocatorPtr;

TranslateResponse
TranslateLogin(AllocatorPtr alloc, const char *socket_path,
	       std::string_view service, std::string_view listener_tag,
	       std::string_view user, std::string_view password);
