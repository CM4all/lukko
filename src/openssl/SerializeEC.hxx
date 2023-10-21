// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <openssl/ec.h>

namespace SSH { class Serializer; }

void
Serialize(SSH::Serializer &s, const EC_POINT &v, const EC_GROUP &g,
	  point_conversion_form_t form=POINT_CONVERSION_UNCOMPRESSED);
