// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "Deserializer.hxx"

#include <cstdint>

namespace SSH {

enum class DisconnectReasonCode : uint32_t;
enum class ChannelExtendedDataType : uint32_t;

struct Disconnect {
	std::string_view description;
	DisconnectReasonCode reason_code;
};

inline auto
ParseDisconnect(std::span<const std::byte> raw)
{
	Disconnect p;
	Deserializer d{raw};
	p.reason_code = static_cast<DisconnectReasonCode>(d.ReadU32());
	p.description = d.ReadString();
	d.ReadString(); // language tag
	d.ExpectEnd();
	return p;
}

struct ServiceRequest {
	std::string_view service_name;
};

inline auto
ParseServiceRequest(std::span<const std::byte> raw)
{
	ServiceRequest p;
	Deserializer d{raw};
	p.service_name = d.ReadString();
	d.ExpectEnd();
	return p;
}

struct ServiceAccept {
	std::string_view service_name;
};

inline auto
ParseServiceAccept(std::span<const std::byte> raw)
{
	ServiceAccept p;
	Deserializer d{raw};
	p.service_name = d.ReadString();
	d.ExpectEnd();
	return p;
}

struct KexInit {
	std::string_view kex_algorithms;
	std::string_view server_host_key_algorithms;
	std::string_view encryption_algorithms_client_to_server;
	std::string_view encryption_algorithms_server_to_client;
	std::string_view mac_algorithms_client_to_server;
	std::string_view mac_algorithms_server_to_client;
};

inline auto
ParseKexInit(std::span<const std::byte> raw)
{
	KexInit p;
	Deserializer d{raw};
	d.ReadN(16); // cookie
	p.kex_algorithms = d.ReadString();
	p.server_host_key_algorithms = d.ReadString();
	p.encryption_algorithms_client_to_server = d.ReadString();
	p.encryption_algorithms_server_to_client = d.ReadString();
	p.mac_algorithms_client_to_server = d.ReadString();
	p.mac_algorithms_server_to_client = d.ReadString();
	d.ReadString(); // compression_algorithms_client_to_server
	d.ReadString(); // compression_algorithms_server_to_client
	d.ReadString(); // languages_client_to_server
	d.ReadString(); // languages_server_to_client
	d.ReadBool(); // first_kex_packet_follows
	d.ReadU32(); // reserved
	d.ExpectEnd();
	return p;
}

struct ECDHKexInit {
	std::span<const std::byte> client_ephemeral_public_key;
};

inline auto
ParseECDHKexInit(std::span<const std::byte> raw)
{
	ECDHKexInit p;
	Deserializer d{raw};
	p.client_ephemeral_public_key = d.ReadLengthEncoded();
	d.ExpectEnd();
	return p;
}

struct ECDHKexInitReply {
	std::span<const std::byte> server_host_key_blob;
	std::span<const std::byte> server_ephemeral_public_key;
	std::span<const std::byte> signature;
};

inline auto
ParseECDHKexInitReply(std::span<const std::byte> raw)
{
	ECDHKexInitReply p;
	Deserializer d{raw};
	p.server_host_key_blob = d.ReadLengthEncoded();
	p.server_ephemeral_public_key = d.ReadLengthEncoded();
	p.signature = d.ReadLengthEncoded();
	d.ExpectEnd();
	return p;
}

struct ChannelOpen {
	std::string_view channel_type;
	uint_least32_t peer_channel;
	uint_least32_t initial_window_size;
	uint_least32_t maximum_packet_size;
	std::span<const std::byte> channel_type_specific_data;
};

inline auto
ParseChannelOpen(std::span<const std::byte> raw)
{
	ChannelOpen p;
	Deserializer d{raw};
	p.channel_type = d.ReadString();
	p.peer_channel = d.ReadU32();
	p.initial_window_size = d.ReadU32();
	p.maximum_packet_size = d.ReadU32();
	p.channel_type_specific_data = d.GetRest();
	return p;
}

struct ChannelOpenConfirmation {
	uint_least32_t local_channel;
	uint_least32_t peer_channel;
	uint_least32_t initial_window_size;
	uint_least32_t maximum_packet_size;
	std::span<const std::byte> channel_type_specific_data;
};

inline auto
ParseChannelOpenConfirmation(std::span<const std::byte> raw)
{
	ChannelOpenConfirmation p;
	Deserializer d{raw};
	p.local_channel = d.ReadU32();
	p.peer_channel = d.ReadU32();
	p.initial_window_size = d.ReadU32();
	p.maximum_packet_size = d.ReadU32();
	p.channel_type_specific_data = d.GetRest();
	return p;
}

struct ChannelOpenFailure {
	uint_least32_t local_channel;
	ChannelOpenFailureReasonCode reason_code;
	std::string_view description;
};

inline auto
ParseChannelOpenFailure(std::span<const std::byte> raw)
{
	ChannelOpenFailure p;
	Deserializer d{raw};
	p.local_channel = d.ReadU32();
	p.reason_code = static_cast<ChannelOpenFailureReasonCode>(d.ReadU32());
	p.description = d.ReadString(); // description
	d.ReadString(); // language_tag;
	d.ExpectEnd();
	return p;
}

struct ChannelWindowAdjust {
	uint_least32_t local_channel;
	uint_least32_t nbytes;
};

inline auto
ParseChannelWindowAdjust(std::span<const std::byte> raw)
{
	ChannelWindowAdjust p;
	Deserializer d{raw};
	p.local_channel = d.ReadU32();
	p.nbytes = d.ReadU32();
	d.ExpectEnd();
	return p;
}

struct ChannelData {
	uint_least32_t local_channel;
	std::span<const std::byte> data;
};

inline auto
ParseChannelData(std::span<const std::byte> raw)
{
	ChannelData p;
	Deserializer d{raw};
	p.local_channel = d.ReadU32();
	p.data = d.ReadLengthEncoded();
	d.ExpectEnd();
	return p;
}

struct ChannelExtendedData {
	uint_least32_t local_channel;
	ChannelExtendedDataType data_type;
	std::span<const std::byte> data;
};

inline auto
ParseChannelExtendedData(std::span<const std::byte> raw)
{
	ChannelExtendedData p;
	Deserializer d{raw};
	p.local_channel = d.ReadU32();
	p.data_type = static_cast<ChannelExtendedDataType>(d.ReadU32());
	p.data = d.ReadLengthEncoded();
	d.ExpectEnd();
	return p;
}

struct ChannelEof {
	uint_least32_t local_channel;
};

inline auto
ParseChannelEof(std::span<const std::byte> raw)
{
	ChannelEof p;
	Deserializer d{raw};
	p.local_channel = d.ReadU32();
	d.ExpectEnd();
	return p;
}

struct ChannelClose {
	uint_least32_t local_channel;
};

inline auto
ParseChannelClose(std::span<const std::byte> raw)
{
	ChannelClose p;
	Deserializer d{raw};
	p.local_channel = d.ReadU32();
	d.ExpectEnd();
	return p;
}

struct ChannelRequest {
	std::string_view request_type;
	std::span<const std::byte> type_specific_data;
	uint_least32_t local_channel;
	bool want_reply;
};

inline auto
ParseChannelRequest(std::span<const std::byte> raw)
{
	ChannelRequest p;
	Deserializer d{raw};
	p.local_channel = d.ReadU32();
	p.request_type = d.ReadString();
	p.want_reply = d.ReadBool();
	p.type_specific_data = d.GetRest();
	return p;
}

struct GlobalRequest {
	std::string_view request_name;
	std::span<const std::byte> request_specific_data;
	bool want_reply;
};

inline auto
ParseGlobalRequest(std::span<const std::byte> raw)
{
	GlobalRequest p;
	Deserializer d{raw};
	p.request_name = d.ReadString();
	p.want_reply = d.ReadBool();
	p.request_specific_data = d.GetRest();
	return p;
}

} // namespace SSH
