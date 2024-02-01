// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "key/TextFile.hxx"
#include "../config.h"

#include <gtest/gtest.h>

using std::string_view_literals::operator""sv;

static constexpr auto authorized_keys = R"ak(
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFL5bCuV5dry+QgfZI5I3faJ9k6qiOx2oH8ebN2MCY4i ed25519a
no-pty,command="echo \"hello, 'world'\"",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMUlI6EKpT1qXL4HrkJtDnJw7pnXVQ7eaLA+yBgwXapF ed25519b
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGc7kQ5VITx7BwuLnGhllruVk0yLdCn2CozIT0Ug9PuIaF21HZFaIkAn9qJ1ZRZgKRiyz3UWpCeJjZl2m+RwA7o= ecdsa
)ak"sv;

static constexpr uint8_t ed25519a[] = {
	0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
	0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0x52, 0xf9, 0x6c, 0x2b, 0x95,
	0xe5, 0xda, 0xf2, 0xf9, 0x08, 0x1f, 0x64, 0x8e, 0x48, 0xdd, 0xf6, 0x89,
	0xf6, 0x4e, 0xaa, 0x88, 0xec, 0x76, 0xa0, 0x7f, 0x1e, 0x6c, 0xdd, 0x8c,
	0x09, 0x8e, 0x22
};

static constexpr uint8_t ed25519b[] = {
	0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
	0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0xc5, 0x25, 0x23, 0xa1, 0x0a,
	0xa5, 0x3d, 0x6a, 0x5c, 0xbe, 0x07, 0xae, 0x42, 0x6d, 0x0e, 0x72, 0x70,
	0xee, 0x99, 0xd7, 0x55, 0x0e, 0xde, 0x68, 0xb0, 0x3e, 0xc8, 0x18, 0x30,
	0x5d, 0xaa, 0x45
};

static constexpr uint8_t ed25519c[] = {
	0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
	0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0x82, 0xfb, 0xc5, 0x35, 0x49,
	0x65, 0x4c, 0x6c, 0x46, 0x29, 0x44, 0x07, 0xd7, 0x1f, 0x6d, 0x65, 0xaa,
	0x23, 0xe4, 0xa2, 0x91, 0x87, 0x5f, 0xb2, 0x20, 0xbb, 0x51, 0xa6, 0x27,
	0x13, 0x19, 0x46
};

static constexpr uint8_t ecdsa[] = {
	0x00, 0x00, 0x00, 0x13, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x73, 0x68,
	0x61, 0x32, 0x2d, 0x6e, 0x69, 0x73, 0x74, 0x70, 0x32, 0x35, 0x36, 0x00,
	0x00, 0x00, 0x08, 0x6e, 0x69, 0x73, 0x74, 0x70, 0x32, 0x35, 0x36, 0x00,
	0x00, 0x00, 0x41, 0x04, 0x67, 0x3b, 0x91, 0x0e, 0x55, 0x21, 0x3c, 0x7b,
	0x07, 0x0b, 0x8b, 0x9c, 0x68, 0x65, 0x96, 0xbb, 0x95, 0x93, 0x4c, 0x8b,
	0x74, 0x29, 0xf6, 0x0a, 0x8c, 0xc8, 0x4f, 0x45, 0x20, 0xf4, 0xfb, 0x88,
	0x68, 0x5d, 0xb5, 0x1d, 0x91, 0x5a, 0x22, 0x40, 0x27, 0xf6, 0xa2, 0x75,
	0x65, 0x16, 0x60, 0x29, 0x18, 0xb2, 0xcf, 0x75, 0x16, 0xa4, 0x27, 0x89,
	0x8d, 0x99, 0x76, 0x9b, 0xe4, 0x70, 0x03, 0xba
};

TEST(AuthorizedKeys, Basic)
{
	EXPECT_TRUE(PublicKeysTextFileContains(authorized_keys,
					       std::as_bytes(std::span{ed25519a})));
	EXPECT_TRUE(PublicKeysTextFileContains(authorized_keys,
						std::as_bytes(std::span{ed25519b})));
	EXPECT_FALSE(PublicKeysTextFileContains(authorized_keys,
						std::as_bytes(std::span{ed25519c})));
	EXPECT_FALSE(PublicKeysTextFileContains(authorized_keys, {}));

#ifdef HAVE_OPENSSL
	EXPECT_TRUE(PublicKeysTextFileContains(authorized_keys,
					       std::as_bytes(std::span{ecdsa})));
#else
	EXPECT_FALSE(PublicKeysTextFileContains(authorized_keys,
						std::as_bytes(std::span{ecdsa})));
#endif
}
