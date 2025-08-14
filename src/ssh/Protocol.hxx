// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "util/PackedBigEndian.hxx"

#include <cstdint>
#include <cstddef>

namespace SSH {

struct PacketHeader {
	PackedBE32 length;
};

static constexpr std::size_t MIN_PACKET_SIZE = 16;
static constexpr std::size_t MIN_PADDING = 4;

constexpr std::size_t
Padding(std::size_t size, std::size_t block_size=8) noexcept
{
	/* minimum packet size is 16 bytes (see RFC 4253 section 6),
	   and since the padding is at least 4 bytes, we need to check
	   only for sizes up to 12 here */
	if (size <= MIN_PACKET_SIZE - MIN_PADDING)
		return MIN_PACKET_SIZE - size;

	return MIN_PADDING + (block_size - 1) - ((size + MIN_PADDING - 1) & (block_size - 1));
}

static_assert(Padding(0) == 16);
static_assert(Padding(7) == 9);
static_assert(Padding(8) == 8);
static_assert(Padding(11) == 5);
static_assert(Padding(12) == 4);
static_assert(Padding(13) == 11);
static_assert(Padding(15) == 9);
static_assert(Padding(16) == 8);
static_assert(Padding(17) == 7);
static_assert(Padding(26) == 6);
static_assert(Padding(28) == 4);
static_assert(Padding(29) == 11);

static_assert(Padding(0, 16) == 16);
static_assert(Padding(7, 16) == 9);
static_assert(Padding(8, 16) == 8);
static_assert(Padding(11, 16) == 5);
static_assert(Padding(12, 16) == 4);
static_assert(Padding(13, 16) == 19);
static_assert(Padding(15, 16) == 17);
static_assert(Padding(16, 16) == 16);
static_assert(Padding(17, 16) == 15);
static_assert(Padding(26, 16) == 6);
static_assert(Padding(28, 16) == 4);
static_assert(Padding(29, 16) == 19);
static_assert(Padding(32, 16) == 16);
static_assert(Padding(33, 16) == 15);

/**
 * @see RFC 4253 section 12
 */
enum class MessageNumber : uint8_t {
	DISCONNECT = 1,
	IGNORE = 2,
	UNIMPLEMENTED = 3,
	DEBUG = 4,
	SERVICE_REQUEST = 5,
	SERVICE_ACCEPT = 6,
	EXT_INFO = 7,
	NEWCOMPRESS = 8,

	KEXINIT = 20,
	NEWKEYS = 21,

	ECDH_KEX_INIT = 30,
	ECDH_KEX_INIT_REPLY = 31,

	USERAUTH_REQUEST = 50,
	USERAUTH_FAILURE = 51,
	USERAUTH_SUCCESS = 52,
	USERAUTH_BANNER = 53,

	USERAUTH_PK_OK = 60,
	USERAUTH_INFO_RESPONSE = 61,

	GLOBAL_REQUEST = 80,
	REQUEST_SUCCESS = 81,
	REQUEST_FAILURE = 82,

	CHANNEL_OPEN = 90,
	CHANNEL_OPEN_CONFIRMATION = 91,
	CHANNEL_OPEN_FAILURE = 92,
	CHANNEL_WINDOW_ADJUST = 93,
	CHANNEL_DATA = 94,
	CHANNEL_EXTENDED_DATA = 95,
	CHANNEL_EOF = 96,
	CHANNEL_CLOSE = 97,
	CHANNEL_REQUEST = 98,
	CHANNEL_SUCCESS = 99,
	CHANNEL_FAILURE = 100,
};

enum class DisconnectReasonCode : uint32_t {
	HOST_NOT_ALLOWED_TO_CONNECT = 1,
	PROTOCOL_ERROR = 2,
	KEY_EXCHANGE_FAILED = 3,
	RESERVED = 4,
	MAC_ERROR = 5,
	COMPRESSION_ERROR = 6,
	SERVICE_NOT_AVAILABLE = 7,
	PROTOCOL_VERSION_NOT_SUPPORTED = 8,
	HOST_KEY_NOT_VERIFIABLE = 9,
	CONNECTION_LOST = 10,
	BY_APPLICATION = 11,
	TOO_MANY_CONNECTIONS = 12,
	AUTH_CANCELLED_BY_USER = 13,
	NO_MORE_AUTH_METHODS_AVAILABLE = 14,
	ILLEGAL_USER_NAME = 15,
};

enum class ChannelOpenFailureReasonCode : uint32_t {
	ADMINISTRATIVELY_PROHIBITED = 1,
	CONNECT_FAILED = 2,
	UNKNOWN_CHANNEL_TYPE = 3,
	RESOURCE_SHORTAGE = 4,
};

enum class ChannelExtendedDataType : uint32_t {
	STDERR = 1,
};

} // namespace SSH
