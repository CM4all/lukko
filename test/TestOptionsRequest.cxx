// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "OptionsRequest.hxx"
#include "key/Options.hxx"
#include "ssh/Serializer.hxx"
#include "ssh/Deserializer.hxx"
#include "memory/fb_pool.hxx"

#include <gtest/gtest.h>

#include <stdexcept>

class OptionsRequest : public testing::Test {
	const ScopeFbPoolInit fb_pool_init;
};

static AuthorizedKeyOptions
RoundTrip(const AuthorizedKeyOptions &options)
{
	SSH::Serializer s;
	SerializeAuthorizedKeyOptions(s, options);

	SSH::Deserializer d{s.Finish()};
	auto result = DeserializeAuthorizedKeyOptions(d);
	d.ExpectEnd();
	return result;
}

TEST_F(OptionsRequest, Empty)
{
	const auto options = RoundTrip({});
	EXPECT_TRUE(options.command.empty());
	EXPECT_FALSE(options.no_port_forwarding);
	EXPECT_FALSE(options.no_pty);
	EXPECT_FALSE(options.home_read_only);
}

TEST_F(OptionsRequest, RoundTrip)
{
	const auto options = RoundTrip({
		.command = "echo \"hello, 'world'\"",
		.no_port_forwarding = true,
		.no_pty = true,
		.home_read_only = true,
	});

	EXPECT_EQ(options.command, "echo \"hello, 'world'\"");
	EXPECT_TRUE(options.no_port_forwarding);
	EXPECT_TRUE(options.no_pty);
	EXPECT_TRUE(options.home_read_only);
}

TEST_F(OptionsRequest, Malformed)
{
	static constexpr uint8_t unknown_option[] = {
		0x00, 0x00, 0x00, 0x03, 'f', 'o', 'o',
		0x00, 0x00, 0x00, 0x00,
	};

	SSH::Deserializer d1{std::as_bytes(std::span{unknown_option})};
	EXPECT_THROW(DeserializeAuthorizedKeyOptions(d1), std::invalid_argument);

	static constexpr uint8_t truncated[] = {
		0x00, 0x00, 0x00, 0x06, 'n', 'o', '-', 'p', 't', 'y',
	};

	SSH::Deserializer d2{std::as_bytes(std::span{truncated})};
	EXPECT_THROW(DeserializeAuthorizedKeyOptions(d2), SSH::MalformedPacket);
}

TEST(Options, Restrict)
{
	/* restrictions are added, but never removed */
	AuthorizedKeyOptions options{.no_pty = true};
	EXPECT_TRUE(options.Restrict({.no_port_forwarding = true}));
	EXPECT_TRUE(options.no_port_forwarding);
	EXPECT_TRUE(options.no_pty);

	EXPECT_TRUE(options.Restrict({}));
	EXPECT_TRUE(options.no_port_forwarding);
	EXPECT_TRUE(options.no_pty);
	EXPECT_TRUE(options.command.empty());

	/* a forced command can be added ... */
	EXPECT_TRUE(options.Restrict({.command = "foo"}));
	EXPECT_EQ(options.command, "foo");

	/* ... and repeated ... */
	EXPECT_TRUE(options.Restrict({.command = "foo"}));
	EXPECT_EQ(options.command, "foo");

	/* ... but never replaced */
	EXPECT_FALSE(options.Restrict({.command = "bar"}));
	EXPECT_EQ(options.command, "foo");
}
