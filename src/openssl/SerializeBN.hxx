// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <openssl/bn.h>

namespace SSH { class Serializer; }

void
Serialize(SSH::Serializer &s, const BIGNUM &bn);
