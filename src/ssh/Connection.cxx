// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Connection.hxx"
#include "KexFactory.hxx"
#include "KexCurve25519.hxx"
#include "KexHash.hxx"
#include "KexProposal.hxx"
#include "Sizes.hxx"
#include "ssh/Protocol.hxx"
#include "ssh/Serializer.hxx"
#include "ssh/MakePacket.hxx"
#include "ssh/Deserializer.hxx"
#include "key/Key.hxx"
#include "key/List.hxx"
#include "key/Algorithms.hxx"
#include "cipher/Cipher.hxx"
#include "cipher/Factory.hxx"
#include "system/Urandom.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "net/SocketError.hxx"
#include "net/SocketProtocolError.hxx"
#include "util/IterableSplitString.hxx"
#include "util/SpanCast.hxx"
#include "Digest.hxx"
#include "version.h"

#ifdef HAVE_OPENSSL
#include "KexECDH.hxx"
#endif

using std::string_view_literals::operator""sv;

namespace SSH {

static constexpr auto g_server_version = "SSH-2.0-CM4all_" VERSION " CM4all\r\n"sv;

static void
SerializeKex(Serializer &s, std::span<const std::byte, KEX_COOKIE_SIZE> cookie,
	     const KexProposal &proposal, bool first_kex_packet_follows=false)
{
	s.WriteN(cookie);
	SerializeProposal(s, proposal);
	s.WriteBool(first_kex_packet_follows);
	s.WriteU32(0); // reserved
}

Connection::Connection(EventLoop &event_loop, UniqueSocketDescriptor _fd,
		       Role _role,
		       const SecretKeyList &_host_keys)
	:host_keys(_host_keys),
	 socket(event_loop),
	 role(_role)
{
	socket.Init(_fd.Release(), FD_TCP,
		    std::chrono::seconds(30),
		    *this);
	socket.ScheduleRead();

	if (socket.DirectWrite(AsBytes(g_server_version)) < 0)
		throw MakeSocketError("Failed to send VersionExchange");
}

Connection::~Connection() noexcept = default;

inline void
Connection::SendPacket(std::span<const std::byte> src)
{
	std::byte encrypted_output[MAX_PACKET_SIZE + 256];

	if (send_cipher) {
		const std::size_t encrypted_size =
			send_cipher->Encrypt(send_seq, src, encrypted_output);
		src = std::span{encrypted_output}.first(encrypted_size);
	}

	++send_seq;

	if (!send_queue.empty()) {
		/* if there is already something in the send_queue,
		   enqueue this packet as well */
		assert(socket.IsWritePending());
		send_queue.Push(src);
		return;
	}

	const auto nbytes = socket.Write(src);
	if (nbytes <= 0) [[unlikely]] {
		switch (static_cast<write_result>(nbytes)) {
		case WRITE_SOURCE_EOF:
			// unreachable
			break;

		case WRITE_ERRNO:
			break;

		case WRITE_BLOCKING:
			send_queue.Push(src);
			OnWriteBlocked();
			return;

		case WRITE_DESTROYED:
			// TODO must not happen, what now?
			return;

		case WRITE_BROKEN:
			break;
		}

		throw MakeSocketError("send failed");
	}

	if (static_cast<std::size_t>(nbytes) < src.size()) [[unlikely]] {
		/* short send: this means the kernel's send buffer is
		   full; push the rest into our send_queue and
		   schedule writing */
		send_queue.Push(src.subspan(nbytes));
		OnWriteBlocked();
		socket.ScheduleWrite();
	}
}

void
Connection::SendPacket(PacketSerializer &&s)
{
	SendPacket(s.Finish(send_cipher != nullptr ? send_cipher->GetBlockSize() : 8,
			    send_cipher != nullptr &&
			    send_cipher->IsHeaderExcludedFromPadding()));
}

void
Connection::SendDisconnect(DisconnectReasonCode reason_code,
			   std::string_view msg)
{
	SendPacket(MakeDisconnect(reason_code, msg));
}

void
Connection::DoDisconnect(DisconnectReasonCode reason_code, std::string_view msg) noexcept
{
	try {
		SendDisconnect(reason_code, msg);
	} catch (...) {
		/* ignore errors, we're going to disconnect anyway */
	}

	Destroy();
}

inline void
Connection::SendKexInit()
{
	PacketSerializer s{MessageNumber::KEXINIT};

	const KexProposal proposal{
		.kex_algorithms = all_kex_algorithms,
		.server_host_key_algorithms = host_keys.GetAlgorithms(),
		.encryption_algorithms_client_to_server = all_encryption_algorithms,
		.encryption_algorithms_server_to_client = all_encryption_algorithms,
		.mac_algorithms_client_to_server = all_mac_algorithms,
		.mac_algorithms_server_to_client = all_mac_algorithms,
		.compression_algorithms_client_to_server = "none"sv,
		.compression_algorithms_server_to_client = "none"sv,
		.languages_client_to_server = ""sv,
		.languages_server_to_client = ""sv,
	};

	std::array<std::byte, KEX_COOKIE_SIZE> cookie;
	UrandomFill(cookie);

	const auto kex_mark = s.Mark();
	SerializeKex(s, cookie, proposal);
	server_kexinit = s.Since(kex_mark);

	SendPacket(std::move(s));
}

inline void
Connection::SendECDHKexInitReply(std::span<const std::byte> client_ephemeral_public_key)
{
	PacketSerializer s{MessageNumber::ECDH_KEX_INIT_REPLY};

	const auto kex_host_key_length = s.PrepareLength();
	const auto kex_host_key_mark = s.Mark();
	host_key->SerializePublic(s);
	s.CommitLength(kex_host_key_length);
	const auto server_host_key_blob = s.Since(kex_host_key_mark);

	const auto server_ephemeral_public_key_length = s.PrepareLength();
	const auto server_ephemeral_public_key_mark = s.Mark();

	Serializer shared_secret;

	switch (kex_algorithm) {
	case KexAlgorithm::CURVE25519_SHA256:
		Curve25519Kex(client_ephemeral_public_key, s, shared_secret);
		break;

#ifdef HAVE_OPENSSL
	case KexAlgorithm::ECDH_SHA256_NISTP256:
		KexECDH(client_ephemeral_public_key, s, shared_secret);
		break;
#endif
	}

	const auto server_ephemeral_public_key = s.Since(server_ephemeral_public_key_mark);
	s.CommitLength(server_ephemeral_public_key_length);

	constexpr auto hash_alg = DigestAlgorithm::SHA256; // TODO

	auto server_version = g_server_version;
	server_version.remove_suffix(2); // remove CR LF

	const auto shared_secret_ = shared_secret.Finish();

	std::byte hash_buffer[DIGEST_MAX_SIZE];
	const auto hashlen = CalcKexHash(hash_alg,
					 client_version,
					 server_version,
					 client_kexinit,
					 server_kexinit,
					 server_host_key_blob,
					 client_ephemeral_public_key,
					 server_ephemeral_public_key,
					 shared_secret_,
					 hash_buffer);

	const auto hash = std::span{hash_buffer}.first(hashlen);

	const auto signature_length = s.PrepareLength();
	host_key->Sign(s, hash, host_key_algorithm);
	s.CommitLength(signature_length);

	SendPacket(std::move(s));

	kex_state.DeriveKeys(hash, shared_secret_, role, true);
}

inline void
Connection::SendNewKeys()
{
	SendPacket(PacketSerializer{MessageNumber::NEWKEYS});

	send_cipher = kex_state.MakeCipher(encryption_algorithms_server_to_client,
					   mac_algorithms_server_to_client,
					   Direction::OUTGOING);
	if (send_cipher == nullptr)
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"No client-to-server encryption algorithm"sv,
		};
}

inline void
Connection::SendExtInfo()
{
	PacketSerializer s{MessageNumber::EXT_INFO};
	s.WriteU32(1);

	/* sending this works around a OpenSSH client bug which causes
	   it to ignore RSA keys; without EXT_INFO,
	   key_sig_algorithm() skips all RSA keys unless "ssh-rsa"
	   (RSA with SHA-1) is explicitly added to option
	   "PubkeyAcceptedAlgorithms", even though we want to use
	   "rsa-sha2-*" */
	s.WriteString("server-sig-algs"sv);
	s.WriteString(all_public_key_algorithms);

	SendPacket(std::move(s));
}

static constexpr bool
StringListContains(std::string_view haystack, std::string_view needle) noexcept
{
	for (const std::string_view i : IterableSplitString(haystack, ','))
		if (i == needle)
			return true;

	return false;
}

inline void
Connection::HandleKexInit(std::span<const std::byte> payload)
{
	client_kexinit = payload;

	Deserializer d{payload};
	d.ReadN(16); // cookie
	const auto kex_algorithms = d.ReadString();
	const auto server_host_key_algorithms = d.ReadString(); // server_host_key_algorithms
	encryption_algorithms_client_to_server.assign(d.ReadString());
	encryption_algorithms_server_to_client.assign(d.ReadString());
	mac_algorithms_client_to_server.assign(d.ReadString());
	mac_algorithms_server_to_client.assign(d.ReadString());
	d.ReadString(); // compression_algorithms_client_to_server
	d.ReadString(); // compression_algorithms_server_to_client
	d.ReadString(); // languages_client_to_server
	d.ReadString(); // languages_server_to_client
	d.ReadBool(); // first_kex_packet_follows
	d.ReadU32(); // reserved
	d.ExpectEnd();

	try {
		kex_algorithm = ChooseKexAlgorithm(kex_algorithms);
	} catch (NoSupportedKexAlgorithm) {
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"No supported KEX algorithm"sv,
		};
	}

	std::tie(host_key, host_key_algorithm) =
		host_keys.Choose(server_host_key_algorithms);
	if (host_key == nullptr)
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"No supported host key"sv,
		};

	peer_wants_ext_info = StringListContains(kex_algorithms,
						 role == Role::SERVER ? "ext-info-c"sv : "ext-info-s"sv);

	SendKexInit();
}

inline void
Connection::HandleNewKeys(std::span<const std::byte> payload)
{
	(void)payload;

	receive_cipher = kex_state.MakeCipher(encryption_algorithms_client_to_server,
					      mac_algorithms_client_to_server,
					      Direction::INCOMING);
	if (receive_cipher == nullptr)
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"No client-to-server encryption algorithm"sv,
		};
}

inline void
Connection::HandleECDHKexInit(std::span<const std::byte> payload)
{
	if (!IsPastKexInit())
		throw Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"No KEXINIT"sv,
		};

	Deserializer d{payload};
	const auto client_ephemeral_public_key = d.ReadLengthEncoded();
	d.ExpectEnd();

	SendECDHKexInitReply(client_ephemeral_public_key);
	SendNewKeys();

	if (peer_wants_ext_info && role == Role::SERVER)
		SendExtInfo();
}

void
Connection::HandlePacket(MessageNumber msg, std::span<const std::byte> payload)
{
	switch (msg) {
	case MessageNumber::DISCONNECT:
		Destroy();
		throw Destroyed{};

	case MessageNumber::IGNORE:
		break;

	case MessageNumber::UNIMPLEMENTED:
		// TODO handle?
		break;

	case MessageNumber::KEXINIT:
		HandleKexInit(payload);
		break;

	case MessageNumber::NEWKEYS:
		HandleNewKeys(payload);
		break;

	case MessageNumber::ECDH_KEX_INIT:
		HandleECDHKexInit(payload);
		break;

	default:
		SendPacket(MakeUnimplemented(receive_seq));
	}
}

inline void
Connection::HandleRawPacket(std::span<const std::byte> payload)
try {
	if (payload.empty())
		throw SocketProtocolError{"Empty packet"};

	const MessageNumber msg = static_cast<MessageNumber>(payload.front());
	payload = payload.subspan(1);

	HandlePacket(msg, payload);
} catch (MalformedPacket) {
	// thrown by class Deserializer
	throw Disconnect{
		DisconnectReasonCode::PROTOCOL_ERROR,
		"Malformed packet"sv,
	};
}

inline AllocatedArray<std::byte>
Connection::DecryptPacket()
{
	assert(receive_cipher);

	const std::size_t need_src = sizeof(PacketHeader) +
		packet_length +
		receive_cipher->GetAuthSize();

	auto r = socket.ReadBuffer();
	if (r.size() < need_src)
		return nullptr;

	r = r.first(need_src);

	AllocatedArray<std::byte> result{packet_length};

	[[maybe_unused]]
	const std::size_t nbytes =
		receive_cipher->DecryptPayload(receive_seq, r, result);
	assert(nbytes == packet_length);
	socket.DisposeConsumed(need_src);

	return result;
}

BufferedResult
Connection::OnBufferedData()
try {
	if (!version_exchanged) {
		const auto r = std::as_bytes(socket.ReadBuffer());
		const auto eol = std::find(r.begin(), r.end(), std::byte{'\n'});
		if (eol == r.end()) {
			if (r.size() >= 255) {
				Destroy();
				return BufferedResult::DESTROYED;
			}

			return BufferedResult::MORE;
		}

		const std::size_t length = std::distance(r.begin(), eol);
		auto s = ToStringView(r.first(length));
		socket.KeepConsumed(length + 1);

		if (!s.starts_with("SSH-"sv)) {
			Destroy();
			return BufferedResult::DESTROYED;
		}

		if (s.ends_with('\r'))
			s.remove_suffix(1);

		client_version.assign(s);

		version_exchanged = true;
	}

	while (true) {
		if (packet_length == 0) {
			/* read a new PacketHeader */

			auto r = socket.ReadBuffer();
			if (r.size() < sizeof(PacketHeader))
				return BufferedResult::MORE;

			if (receive_cipher) {
				PacketHeader header;
				receive_cipher->DecryptHeader(receive_seq,
							      r.first<sizeof(header)>(),
							      ReferenceAsWritableBytes(header));
				packet_length = header.length;
			} else {
				const auto &header = *reinterpret_cast<const PacketHeader *>(r.data());
				packet_length = header.length;
				socket.DisposeConsumed(sizeof(header));
			}

			if (packet_length == 0)
				/* packets cannot be empty, there must
				   be at least the "padding_length"
				   byte (plus mandatory padding) */
				throw SocketProtocolError{"Empty packet"};

			if (packet_length > MAX_PACKET_SIZE)
				throw SocketProtocolError{"Packet too large"};
		}

		std::span<const std::byte> r;

		AllocatedArray<std::byte> decrypted;
		if (receive_cipher) {
			decrypted = DecryptPacket();
			if (decrypted == nullptr)
				return BufferedResult::MORE;

			r = decrypted;
			assert(r.size() == packet_length);
		} else
			r = socket.ReadBuffer();

		if (r.size() < packet_length)
			return BufferedResult::MORE;

		const std::size_t padding_length = static_cast<uint8_t>(r.front());
		if (padding_length > packet_length - 1) {
			Destroy();
			return BufferedResult::DESTROYED;
		}

		if (!receive_cipher)
			socket.KeepConsumed(packet_length);

		const auto payload = r.subspan(1, packet_length - padding_length - 1);
		packet_length = 0;

		HandleRawPacket(payload);

		++receive_seq;
	}
} catch (const Disconnect &d) {
	DoDisconnect(d.reason_code, d.msg);
	return BufferedResult::DESTROYED;
} catch (const Destroyed &) {
	return BufferedResult::DESTROYED;
}

bool
Connection::OnBufferedWrite()
{
	OnWriteUnblocked();

	std::array<struct iovec, 32> v;
	std::size_t n = send_queue.Prepare(v);
	if (n == 0) {
		socket.UnscheduleWrite();
		return true;
	}

	const auto nbytes = socket.WriteV(std::span{v}.first(n));
	if (nbytes < 0) [[unlikely]] {
		switch (static_cast<write_result>(nbytes)) {
		case WRITE_SOURCE_EOF:
			// unreachable
			break;

		case WRITE_ERRNO:
			break;

		case WRITE_BLOCKING:
			return true;

		case WRITE_DESTROYED:
			return false;

		case WRITE_BROKEN:
			break;
		}

		throw MakeSocketError("send failed");
	}

	send_queue.Consume(nbytes);
	if (send_queue.empty())
		socket.UnscheduleWrite();

	return true;
}

bool
Connection::OnBufferedClosed() noexcept
{
	Destroy();
	return false;
}

void
Connection::OnBufferedError([[maybe_unused]] std::exception_ptr e) noexcept
{
	Destroy();
}

} // namespace SSH
