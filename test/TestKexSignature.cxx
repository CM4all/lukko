// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "key/Ed25519Key.hxx"
#include "key/Key.hxx"
#include "ssh/KexSignature.hxx"
#include "ssh/Serializer.hxx"
#include "util/AllocatedArray.hxx"
#include "util/SpanCast.hxx"
#include "memory/fb_pool.hxx"

#include <gtest/gtest.h>

using std::string_view_literals::operator""sv;

static AllocatedArray<std::byte>
SerializePublicKey(const PublicKey &key)
{
	SSH::Serializer s;
	key.SerializePublic(s);
	return AllocatedArray{s.Finish()};
}

static AllocatedArray<std::byte>
SignKexHash(const SecretKey &key, std::span<const std::byte> hash,
	    std::string_view algorithm)
{
	SSH::Serializer s;
	key.Sign(s, hash, algorithm);
	return AllocatedArray{s.Finish()};
}

TEST(KexSignature, VerifyEd25519)
{
	const ScopeFbPoolInit fb_pool_init;
	const Ed25519Key key{Ed25519Key::Generate{}};
	const auto public_key_blob = SerializePublicKey(key);
	const std::span<const std::byte> hash{AsBytes("Hello world"sv)};
	auto signature = SignKexHash(key, hash, "ssh-ed25519"sv);

	EXPECT_TRUE(SSH::VerifyKexSignature(public_key_blob, hash, signature));

	signature[signature.size() - 1] ^= std::byte{1};
	EXPECT_FALSE(SSH::VerifyKexSignature(public_key_blob, hash, signature));
}
