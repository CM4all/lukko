// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <openssl/evp.h>

namespace SSH { class Serializer; }

void
SerializePublicKey(SSH::Serializer &s, const EVP_PKEY &key);
