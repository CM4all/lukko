// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "ssh/Serializer.hxx"

#include <gtest/gtest.h>

TEST(WriteBignum2, Empty)
{
	SSH::Serializer s;
	s.WriteBignum2({});

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 4U);
	EXPECT_EQ(result[0], std::byte{0});
	EXPECT_EQ(result[1], std::byte{0});
	EXPECT_EQ(result[2], std::byte{0});
	EXPECT_EQ(result[3], std::byte{0});
}

TEST(WriteBignum2, Zero)
{
	static constexpr std::array data{std::byte{}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 4U);
	EXPECT_EQ(result[0], std::byte{0});
	EXPECT_EQ(result[1], std::byte{0});
	EXPECT_EQ(result[2], std::byte{0});
	EXPECT_EQ(result[3], std::byte{0});
}

TEST(WriteBignum2, One)
{
	static constexpr std::array data{std::byte{42}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 5U);
	EXPECT_EQ(result[0], std::byte{0});
	EXPECT_EQ(result[1], std::byte{0});
	EXPECT_EQ(result[2], std::byte{0});
	EXPECT_EQ(result[3], std::byte{1});
	EXPECT_EQ(result[4], std::byte{42});
}

TEST(WriteBignum2, LeadingZeroes)
{
	static constexpr std::array data{std::byte{}, std::byte{}, std::byte{42}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 5U);
	EXPECT_EQ(result[0], std::byte{0});
	EXPECT_EQ(result[1], std::byte{0});
	EXPECT_EQ(result[2], std::byte{0});
	EXPECT_EQ(result[3], std::byte{1});
	EXPECT_EQ(result[4], std::byte{42});
}

TEST(WriteBignum2, NotNegative)
{
	static constexpr std::array data{std::byte{42}, std::byte{0xff}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 6U);
	EXPECT_EQ(result[0], std::byte{0});
	EXPECT_EQ(result[1], std::byte{0});
	EXPECT_EQ(result[2], std::byte{0});
	EXPECT_EQ(result[3], std::byte{2});
	EXPECT_EQ(result[4], std::byte{42});
	EXPECT_EQ(result[5], std::byte{0xff});
}

TEST(WriteBignum2, Negative)
{
	static constexpr std::array data{std::byte{0x80}, std::byte{42}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 7U);
	EXPECT_EQ(result[0], std::byte{0});
	EXPECT_EQ(result[1], std::byte{0});
	EXPECT_EQ(result[2], std::byte{0});
	EXPECT_EQ(result[3], std::byte{3});
	EXPECT_EQ(result[4], std::byte{});
	EXPECT_EQ(result[5], std::byte{0x80});
	EXPECT_EQ(result[6], std::byte{42});
}

TEST(WriteBignum2, NegativeWithLeadingZeroes)
{
	static constexpr std::array data{std::byte{}, std::byte{}, std::byte{0x80}, std::byte{42}};
	SSH::Serializer s;
	s.WriteBignum2(data);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 7U);
	EXPECT_EQ(result[0], std::byte{0});
	EXPECT_EQ(result[1], std::byte{0});
	EXPECT_EQ(result[2], std::byte{0});
	EXPECT_EQ(result[3], std::byte{3});
	EXPECT_EQ(result[4], std::byte{});
	EXPECT_EQ(result[5], std::byte{0x80});
	EXPECT_EQ(result[6], std::byte{42});
}