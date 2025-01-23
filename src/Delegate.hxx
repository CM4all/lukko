// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <string_view>

namespace Co { template<typename T> class Task; }
class UniqueFileDescriptor;
class Connection;

/**
 * Open a file with the uid of the given user.
 */
Co::Task<UniqueFileDescriptor>
DelegateOpen(const Connection &ssh_connection, std::string_view path);

Co::Task<UniqueFileDescriptor>
DelegateLocalConnect(const Connection &ssh_connection, std::string_view path);
