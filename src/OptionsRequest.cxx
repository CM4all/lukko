// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "OptionsRequest.hxx"
#include "key/Options.hxx"
#include "ssh/Serializer.hxx"
#include "ssh/Deserializer.hxx"

#include <stdexcept>

using std::string_view_literals::operator""sv;

static void
SerializeOption(SSH::Serializer &s, std::string_view name,
		std::string_view value)
{
	s.WriteString(name);
	s.WriteString(value);
}

void
SerializeAuthorizedKeyOptions(SSH::Serializer &s,
			      const AuthorizedKeyOptions &options)
{
	if (!options.command.empty())
		SerializeOption(s, "command"sv, options.command);

	if (options.no_port_forwarding)
		SerializeOption(s, "no-port-forwarding"sv, {});

	if (options.no_pty)
		SerializeOption(s, "no-pty"sv, {});

	if (options.home_read_only)
		SerializeOption(s, "home-read-only"sv, {});
}

AuthorizedKeyOptions
DeserializeAuthorizedKeyOptions(SSH::Deserializer &d)
{
	AuthorizedKeyOptions options;

	while (!d.GetRest().empty()) {
		const auto name = d.ReadString();
		std::string value{d.ReadString()};

		if (!options.Set(name, std::move(value)))
			throw std::invalid_argument{"Unsupported authorized_keys option"};
	}

	return options;
}
