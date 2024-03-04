// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "openssl/BN.hxx"
#include "openssl/SerializeBN.hxx"
#include "ssh/Serializer.hxx"
#include "lib/openssl/Error.hxx"
#include "memory/fb_pool.hxx"

#include <gtest/gtest.h>

static auto
BN_hex2bn(const char *str)
{
	BIGNUM *bn = nullptr;
	const int result = BN_hex2bn(&bn, str);
	if (result <= 0)
		throw SslError{"BN_hex2bn() failed"};

	if (static_cast<std::size_t>(result) != strlen(str))
		throw std::invalid_argument{"BN_hex2bn() failed"};

	return UniqueBIGNUM<false>{bn};
}

class SerializeBignum : public testing::Test {
	const ScopeFbPoolInit fb_pool_init;
};

TEST_F(SerializeBignum, One)
{
	SSH::Serializer s;
	Serialize(s, *BN_hex2bn("42"));

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 1U);
	EXPECT_EQ(result[0], std::byte{0x42});
}

TEST_F(SerializeBignum, Two)
{
	SSH::Serializer s;
	Serialize(s, *BN_hex2bn("1234"));

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 2U);
	EXPECT_EQ(result[0], std::byte{0x12});
	EXPECT_EQ(result[1], std::byte{0x34});
}

TEST_F(SerializeBignum, Odd)
{
	SSH::Serializer s;
	Serialize(s, *BN_hex2bn("123"));

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 2U);
	EXPECT_EQ(result[0], std::byte{0x01});
	EXPECT_EQ(result[1], std::byte{0x23});
}

TEST_F(SerializeBignum, Negative)
{
	SSH::Serializer s;
	Serialize(s, *BN_hex2bn("8042"));

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 3U);
	/* must have inserted a null byte */
	EXPECT_EQ(result[0], std::byte{});
	EXPECT_EQ(result[1], std::byte{0x80});
	EXPECT_EQ(result[2], std::byte{0x42});
}

TEST_F(SerializeBignum, LeadingZero)
{
	SSH::Serializer s;
	Serialize(s, *BN_hex2bn("001234"));

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 2U);
	EXPECT_EQ(result[0], std::byte{0x12});
	EXPECT_EQ(result[1], std::byte{0x34});
}

TEST_F(SerializeBignum, SetLeadingZero)
{
	const auto bn = BN_hex2bn("ff123456");

	/* clear all bits in the highest byte; there must not be any
	   leading zeroes in the output */
	for (int i = 24; i < 32; ++i)
		BN_clear_bit(bn.get(), i);

	SSH::Serializer s;
	Serialize(s, *bn);

	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 3U);
	EXPECT_EQ(result[0], std::byte{0x12});
	EXPECT_EQ(result[1], std::byte{0x34});
	EXPECT_EQ(result[2], std::byte{0x56});
}

TEST_F(SerializeBignum, Long)
{
	SSH::Serializer s;
	Serialize(s, *BN_hex2bn("2fd887b60bc3b6790ae974473df38114b91381c641d7023655002d7083a512"));
	const auto result = s.Finish();
	ASSERT_EQ(result.size(), 31U);
	EXPECT_EQ(result.front(), std::byte{0x2f});
	EXPECT_EQ(result.back(), std::byte{0x12});
}
