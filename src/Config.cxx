// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Config.hxx"
#include "DebugMode.hxx"
#include "spawn/ConfigParser.hxx"
#include "net/IPv6Address.hxx"
#include "net/Parser.hxx"
#include "net/control/Protocol.hxx"
#include "io/config/FileLineParser.hxx"
#include "io/config/ConfigParser.hxx"
#include "util/StringAPI.hxx"

#ifdef HAVE_AVAHI
#include "lib/avahi/Check.hxx"
#endif

// not defaulting to 22 until this project is fully-featured
static constexpr unsigned LUKKO_DEFAULT_PORT = 2200;

Config::Config()
{
	if (!debug_mode)
		spawn.spawner_uid_gid.Lookup("cm4all-lukko-spawn");

	if (debug_mode)
		spawn.default_uid_gid.LoadEffective();

	// TODO implement SpawnConfig properly
	spawn.allow_any_uid_gid = true;

#ifdef HAVE_LIBSYSTEMD
	spawn.systemd_scope = "lukko-spawn.scope";
	spawn.systemd_scope_description = "The Lukko child process spawner";
	spawn.systemd_slice = "system-cm4all.slice";
#endif
}

void
Config::Check()
{
	if (listeners.empty()) {
		listeners.emplace_front();
		auto &l = listeners.front();
		l.bind_address = IPv6Address{LUKKO_DEFAULT_PORT};
		l.listen = 256;
		l.tcp_user_timeout = 60000;
		l.tcp_no_delay = true;
		l.keepalive = true;
	}

	if (debug_mode)
		/* accept gid=0 (keep current gid) from translation
		   server if we were started as unprivileged user */
		spawn.allowed_gids.insert(0);
}

class LukkoConfigParser final : public NestedConfigParser {
	Config &config;

	class Listener final : public ConfigParser {
		Config &parent;
		ListenerConfig config;

	public:
		explicit Listener(Config &_parent):parent(_parent) {}

	protected:
		/* virtual methods from class ConfigParser */
		void ParseLine(FileLineParser &line) override;
		void Finish() override;
	};

#ifdef ENABLE_CONTROL
	class Control final : public ConfigParser {
		Config &parent;
		Config::ControlListener config;

	public:
		explicit Control(Config &_parent) noexcept:parent(_parent) {}

	protected:
		/* virtual methods from class ConfigParser */
		void ParseLine(FileLineParser &line) override;
		void Finish() override;
	};
#endif // ENABLE_CONTROL

public:
	explicit LukkoConfigParser(Config &_config) noexcept
		:config(_config) {}

protected:
	/* virtual methods from class NestedConfigParser */
	void ParseLine2(FileLineParser &line) override;
};

void
LukkoConfigParser::Listener::ParseLine(FileLineParser &line)
{
	const char *word = line.ExpectWord();

	if (StringIsEqual(word, "bind")) {
		config.bind_address = ParseSocketAddress(line.ExpectValueAndEnd(),
							 LUKKO_DEFAULT_PORT, true);
	} else if (StringIsEqual(word, "interface")) {
		config.interface = line.ExpectValueAndEnd();
	} else if (StringIsEqual(word, "mode")) {
		if (config.bind_address.IsNull() ||
		    config.bind_address.GetFamily() != AF_LOCAL)
			throw LineParser::Error("'mode' works only with local sockets");

		const char *s = line.ExpectValueAndEnd();
		char *endptr;
		const unsigned long value = strtoul(s, &endptr, 8);
		if (endptr == s || *endptr != 0)
			throw LineParser::Error("Not a valid octal value");

		if (value & ~0777ULL)
			throw LineParser::Error("Not a valid mode");

		config.mode = value;
	} else if (StringIsEqual(word, "mptcp")) {
		config.mptcp = line.NextBool();
		line.ExpectEnd();
	} else if (StringIsEqual(word, "ack_timeout")) {
		config.tcp_user_timeout = line.NextPositiveInteger() * 1000;
		line.ExpectEnd();
	} else if (StringIsEqual(word, "keepalive")) {
		config.keepalive = line.NextBool();
		line.ExpectEnd();
	} else if (StringIsEqual(word, "v6only")) {
		config.v6only = line.NextBool();
		line.ExpectEnd();
	} else if (StringIsEqual(word, "reuse_port")) {
		config.reuse_port = line.NextBool();
		line.ExpectEnd();
	} else if (StringIsEqual(word, "zeroconf_service")) {
#ifdef HAVE_AVAHI
		config.zeroconf_service = MakeZeroconfServiceType(line.ExpectValueAndEnd(),
								  "_tcp");
#else
		throw std::runtime_error{"Zeroconf support is disabled"};
#endif // HAVE_AVAHI
	} else if (StringIsEqual(word, "tag")) {
#ifdef ENABLE_TRANSLATION
		config.tag = line.ExpectValueAndEnd();
#endif // ENABLE_TRANSLATION
	} else if (StringIsEqual(word, "proxy_to")) {
		// TODO experimental feature
		config.proxy_to = ParseSocketAddress(line.ExpectValueAndEnd(),
						     22, false);
	} else
		throw LineParser::Error("Unknown option");
}

void
LukkoConfigParser::Listener::Finish()
{
	if (config.bind_address.IsNull())
		throw LineParser::Error("Listener has no bind address");

	config.Fixup();

	parent.listeners.emplace_front(std::move(config));

	ConfigParser::Finish();
}

#ifdef ENABLE_CONTROL

void
LukkoConfigParser::Control::ParseLine(FileLineParser &line)
{
	const char *word = line.ExpectWord();

	if (StringIsEqual(word, "bind")) {
		config.bind_address = ParseSocketAddress(line.ExpectValueAndEnd(),
							 BengControl::DEFAULT_PORT, true);
	} else if (StringIsEqual(word, "multicast_group")) {
		config.multicast_group = ParseSocketAddress(line.ExpectValueAndEnd(),
							    0, false);
	} else if (StringIsEqual(word, "interface")) {
		config.interface = line.ExpectValueAndEnd();
	} else
		throw LineParser::Error("Unknown option");
}

void
LukkoConfigParser::Control::Finish()
{
	if (config.bind_address.IsNull())
		throw LineParser::Error("Bind address is missing");

	config.Fixup();

	parent.control_listeners.emplace_front(std::move(config));

	ConfigParser::Finish();
}

#endif // ENABLE_CONTROL

void
LukkoConfigParser::ParseLine2(FileLineParser &line)
{
	const char *word = line.ExpectWord();

	if (StringIsEqual(word, "listener")) {
		line.ExpectSymbolAndEol('{');
		SetChild(std::make_unique<Listener>(config));
	} else if (StringIsEqual(word, "spawn")) {
		line.ExpectSymbolAndEol('{');
		SetChild(std::make_unique<SpawnConfigParser>(config.spawn));
#ifdef ENABLE_TRANSLATION
	} else if (StringIsEqual(word, "translation_server")) {
		config.translation_server = line.ExpectValueAndEnd();
#endif // ENABLE_TRANSLATION
#ifdef ENABLE_CONTROL
	} else if (StringIsEqual(word, "control")) {
		line.ExpectSymbolAndEol('{');
		SetChild(std::make_unique<Control>(config));
#endif // ENABLE_CONTROL
	} else
		throw LineParser::Error("Unknown option");
}

void
LoadConfigFile(Config &config, const char *path)
{
	LukkoConfigParser parser(config);
	VariableConfigParser v_parser(parser);
	CommentConfigParser parser2(v_parser);
	IncludeConfigParser parser3(path, parser2);

	ParseConfigFile(path, parser3);
}
