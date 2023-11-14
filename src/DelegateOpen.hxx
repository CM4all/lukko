// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <string_view>

class UniqueFileDescriptor;
class Connection;

/**
 * Open a file with the uid of the given user.
 */
UniqueFileDescriptor
DelegateOpen(const Connection &ssh_connection, std::string_view path);
