// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <memory>

class FileDescriptor;
class SecretKey;

std::unique_ptr<SecretKey>
LoadKeyFile(FileDescriptor fd);
