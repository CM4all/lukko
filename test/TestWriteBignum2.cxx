// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "ssh/Serializer.hxx"
#include "memory/fb_pool.hxx"

#include <gtest/gtest.h>

class WriteBignum2 : public testing::Test {
	const ScopeFbPoolInit fb_pool_init;
};

TEST_F(WriteBignum2, Empty)
{
	SSH::Serializer s;
	s.WriteBignum2({});

	const auto result = s.Finish();
	EXPECT_TRUE(result.empty());
}

TEST_F(WriteBignum2, Zero)
{
	static constexpr std::array data{std::byte{}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	EXPECT_TRUE(result.empty());
}

TEST_F(WriteBignum2, One)
{
	static constexpr std::array data{std::byte{42}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 1U);
	EXPECT_EQ(result[0], std::byte{42});
}

TEST_F(WriteBignum2, LeadingZeroes)
{
	static constexpr std::array data{std::byte{}, std::byte{}, std::byte{42}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 1U);
	EXPECT_EQ(result[0], std::byte{42});
}

TEST_F(WriteBignum2, NotNegative)
{
	static constexpr std::array data{std::byte{42}, std::byte{0xff}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 2);
	EXPECT_EQ(result[0], std::byte{42});
	EXPECT_EQ(result[1], std::byte{0xff});
}

TEST_F(WriteBignum2, Negative)
{
	static constexpr std::array data{std::byte{0x80}, std::byte{42}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 3U);
	EXPECT_EQ(result[0], std::byte{});
	EXPECT_EQ(result[1], std::byte{0x80});
	EXPECT_EQ(result[2], std::byte{42});
}

TEST_F(WriteBignum2, NegativeWithLeadingZeroes)
{
	static constexpr std::array data{std::byte{}, std::byte{}, std::byte{0x80}, std::byte{42}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 3U);
	EXPECT_EQ(result[0], std::byte{});
	EXPECT_EQ(result[1], std::byte{0x80});
	EXPECT_EQ(result[2], std::byte{42});
}
