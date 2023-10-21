// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "KexHash.hxx"
#include "Protocol.hxx"
#include "util/ByteOrder.hxx"
#include "util/SpanCast.hxx"

namespace SSH {

std::size_t
CalcKexHash(DigestAlgorithm hash_alg,
	    std::string_view client_version,
	    std::string_view server_version,
	    std::span<const std::byte> client_kexinit,
	    std::span<const std::byte> server_kexinit,
	    std::span<const std::byte> server_host_key_blob,
	    std::span<const std::byte> client_ephemeral_public_key,
	    std::span<const std::byte> server_ephemeral_public_key,
	    std::span<const std::byte> shared_secret,
	    std::byte *hash)
{
	const uint32_t client_version_length = ToBE32(client_version.size());
	const uint32_t server_version_length = ToBE32(server_version.size());
	const uint32_t client_kexinit_size = ToBE32(client_kexinit.size() + 1);
	const uint32_t server_kexinit_size = ToBE32(server_kexinit.size() + 1);
	const uint32_t server_host_key_blob_size = ToBE32(server_host_key_blob.size());
	const uint32_t client_ephemeral_public_key_size = ToBE32(client_ephemeral_public_key.size());
	const uint32_t server_ephemeral_public_key_size = ToBE32(server_ephemeral_public_key.size());

	const uint8_t kexinit_msg_number = static_cast<uint8_t>(MessageNumber::KEXINIT);

	return Digest(hash_alg, {
			ReferenceAsBytes(client_version_length),
			AsBytes(client_version),
			ReferenceAsBytes(server_version_length),
			AsBytes(server_version),
			ReferenceAsBytes(client_kexinit_size),
			ReferenceAsBytes(kexinit_msg_number),
			client_kexinit,
			ReferenceAsBytes(server_kexinit_size),
			ReferenceAsBytes(kexinit_msg_number),
			server_kexinit,
			ReferenceAsBytes(server_host_key_blob_size),
			server_host_key_blob,
			ReferenceAsBytes(client_ephemeral_public_key_size),
			client_ephemeral_public_key,
			ReferenceAsBytes(server_ephemeral_public_key_size),
			server_ephemeral_public_key,
			shared_secret,
		}, hash);
}

} // namespace SSH
