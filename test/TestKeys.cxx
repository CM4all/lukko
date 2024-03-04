// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "key/Ed25519Key.hxx"
#include "key/Parser.hxx"
#include "key/Set.hxx"
#include "ssh/Serializer.hxx"
#include "util/AllocatedArray.hxx"
#include "util/IterableSplitString.hxx"
#include "util/SpanCast.hxx"
#include "memory/fb_pool.hxx"
#include "../config.h"

#ifdef HAVE_OPENSSL
#include "key/RSAKey.hxx"
#include "key/ECDSAKey.hxx"
#endif // HAVE_OPENSSL

#include <gtest/gtest.h>

using std::string_view_literals::operator""sv;

static AllocatedArray<std::byte>
Sign(const SecretKey &key, std::span<const std::byte> message,
     std::string_view algorithm)
{
	SSH::Serializer s;
	key.Sign(s, message, algorithm);
	return AllocatedArray{s.Finish()};
}

static std::unique_ptr<PublicKey>
SerializeDeserialize(const PublicKey &key)
{
	SSH::Serializer s;
	key.SerializePublic(s);
	return ParsePublicKeyBlob(s.Finish());
}

static void
TestKey(const SecretKey &key, std::string_view algorithm)
{
	const std::span<const std::byte> message{AsBytes("Hello world"sv)};

	const auto signature = Sign(key, message, algorithm);
	EXPECT_TRUE(key.Verify(message, signature));

	const auto public_key = SerializeDeserialize(key);
	EXPECT_EQ(key.GetType(), public_key->GetType());
	EXPECT_EQ(key.GetAlgorithms(), public_key->GetAlgorithms());
	EXPECT_TRUE(public_key->Verify(message, signature));
}

static void
TestKey(const SecretKey &key)
{
	for (const std::string_view a : IterableSplitString(key.GetAlgorithms(), ','))
		TestKey(key, a);
}

TEST(Ed25519Key, TestKey)
{
	const ScopeFbPoolInit fb_pool_init;
	const Ed25519Key key{Ed25519Key::Generate{}};
	TestKey(key);
}

#ifdef HAVE_OPENSSL

TEST(RSAKey, TestKey)
{
	const ScopeFbPoolInit fb_pool_init;
	const RSAKey key{RSAKey::Generate{}};
	TestKey(key);
}

TEST(ECDSAKey, TestKey)
{
	const ScopeFbPoolInit fb_pool_init;
	const ECDSAKey key{ECDSAKey::Generate{}};
	TestKey(key);
}

#endif // HAVE_OPENSSL

TEST(PublicKeySet, Basic)
{
	const ScopeFbPoolInit fb_pool_init;
	const Ed25519Key key1{Ed25519Key::Generate{}}, key2{Ed25519Key::Generate{}};

	PublicKeySet s;
	EXPECT_FALSE(s.Find(key1));
	EXPECT_FALSE(s.Find(key2));

	s.Add(key1);
	EXPECT_TRUE(s.Find(key1));
	EXPECT_FALSE(s.Find(key2));

	s.Add(key2);
	EXPECT_TRUE(s.Find(key1));
	EXPECT_TRUE(s.Find(key2));
}
