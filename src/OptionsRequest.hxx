// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include <string_view>

struct AuthorizedKeyOptions;

namespace SSH {
class Serializer;
class Deserializer;
}

/**
 * The name of the GLOBAL_REQUEST which transports the
 * #AuthorizedKeyOptions of the real client to the target server in
 * proxy mode.  This is necessary because the proxy authenticates on
 * the target server with the "hostbased" method which knows nothing
 * about the "authorized_keys" options of the real client.
 *
 * The request-specific data is a list of name/value pairs (each one a
 * SSH string) using the same vocabulary as the "authorized_keys"
 * file; only options which impose a restriction are transmitted.
 */
constexpr std::string_view AUTHORIZED_KEY_OPTIONS_REQUEST =
	"authorized-key-options@lukko.cm4all.com";

/**
 * Serialize all restrictions of the given #AuthorizedKeyOptions into
 * the request-specific data of #AUTHORIZED_KEY_OPTIONS_REQUEST.
 *
 * Throws on error.
 */
void
SerializeAuthorizedKeyOptions(SSH::Serializer &s,
			      const AuthorizedKeyOptions &options);

/**
 * The inverse of SerializeAuthorizedKeyOptions().
 *
 * Throws if the payload is malformed or contains an unsupported
 * option (which must not be ignored silently because that would lift
 * a restriction).
 */
AuthorizedKeyOptions
DeserializeAuthorizedKeyOptions(SSH::Deserializer &d);
