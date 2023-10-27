// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "key/Ed25519Key.hxx"
#include "key/Parser.hxx"
#include "ssh/Serializer.hxx"
#include "util/AllocatedArray.hxx"
#include "util/SpanCast.hxx"
#include "../config.h"

#ifdef HAVE_OPENSSL
#include "key/RSAKey.hxx"
#include "key/ECDSAKey.hxx"
#endif // HAVE_OPENSSL

#include <gtest/gtest.h>

using std::string_view_literals::operator""sv;

static AllocatedArray<std::byte>
Sign(const SecretKey &key, std::span<const std::byte> message)
{
	SSH::Serializer s;
	key.Sign(s, message);
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
TestKey(const SecretKey &key)
{
	const std::span<const std::byte> message{AsBytes("Hello world"sv)};

	const auto signature = Sign(key, message);
	EXPECT_TRUE(key.Verify(message, signature));

	const auto public_key = SerializeDeserialize(key);
	EXPECT_EQ(key.GetAlgorithm(), public_key->GetAlgorithm());
	EXPECT_TRUE(public_key->Verify(message, signature));
}

TEST(Ed25519Key, TestKey)
{
	const Ed25519Key key{Ed25519Key::Generate{}};
	TestKey(key);
}

#ifdef HAVE_OPENSSL

TEST(RSAKey, TestKey)
{
	const RSAKey key{RSAKey::Generate{}};
	TestKey(key);
}

TEST(ECDSAKey, TestKey)
{
	const ECDSAKey key{ECDSAKey::Generate{}};
	TestKey(key);
}

#endif // HAVE_OPENSSL
