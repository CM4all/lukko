// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <string>

class PublicKey;

std::string
GetFingerprint(const PublicKey &key) noexcept;
