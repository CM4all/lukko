// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Connection.hxx"
#include "Input.hxx"
#include "Output.hxx"
#include "KexInterface.hxx"
#include "KexFactory.hxx"
#include "KexHash.hxx"
#include "KexProposal.hxx"
#include "Sizes.hxx"
#include "ssh/Protocol.hxx"
#include "ssh/Serializer.hxx"
#include "ssh/MakePacket.hxx"
#include "ssh/Deserializer.hxx"
#include "key/Key.hxx"
#include "key/Algorithms.hxx"
#include "cipher/Cipher.hxx"
#include "cipher/Factory.hxx"
#include "thread/Pool.hxx"
#include "system/Urandom.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "net/SocketError.hxx"
#include "net/SocketProtocolError.hxx"
#include "util/IterableSplitString.hxx"
#include "util/SpanCast.hxx"
#include "Digest.hxx"
#include "version.h"

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
		       Role _role)
	:socket(event_loop),
	 input(*new Input(thread_pool_get_queue(event_loop), *this)),
	 output(*new Output(thread_pool_get_queue(event_loop), socket)),
	 role(_role)
{
	socket.Init(_fd.Release(), FD_TCP,
		    std::chrono::seconds(30),
		    *this);
	socket.ScheduleRead();

	if (socket.DirectWrite(AsBytes(g_server_version)) < 0)
		throw MakeSocketError("Failed to send VersionExchange");
}

Connection::~Connection() noexcept
{
	output.Destroy();
	input.Destroy();
}

bool
Connection::IsEncrypted() const noexcept
{
	return input.IsEncrypted() && output.IsEncrypted();
}

inline void
Connection::SendPacket(std::span<const std::byte> src)
{
	output.Push(src);
	socket.DeferWrite();
}

void
Connection::SendPacket(PacketSerializer &&s)
{
	const auto *send_cipher = output.GetCipher();
	SendPacket(s.Finish(send_cipher
			    != nullptr ? send_cipher->GetBlockSize() : 8,
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

std::string_view
Connection::GetServerHostKeyAlgorithms() const noexcept
{
	return all_public_key_algorithms;
}

inline void
Connection::SendKexInit()
{
	PacketSerializer s{MessageNumber::KEXINIT};

	KexProposal proposal{
		.kex_algorithms = role == Role::SERVER ? all_server_kex_algorithms : all_client_kex_algorithms,
		.server_host_key_algorithms = GetServerHostKeyAlgorithms(),
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
	my_kexinit = s.Since(kex_mark);

	SendPacket(std::move(s));
}

inline void
Connection::SendECDHKexInit()
{
	assert(role == Role::CLIENT);
	assert(kex_algorithm);

	PacketSerializer s{MessageNumber::ECDH_KEX_INIT};

	const auto ephemeral_public_key_length = s.PrepareLength();
	kex_algorithm->SerializeEphemeralPublicKey(s);
	s.CommitLength(ephemeral_public_key_length);

	SendPacket(std::move(s));
}

inline void
Connection::SendECDHKexInitReply(std::span<const std::byte> client_ephemeral_public_key)
{
	assert(role == Role::SERVER);
	assert(kex_algorithm);

	PacketSerializer s{MessageNumber::ECDH_KEX_INIT_REPLY};

	const auto kex_host_key_length = s.PrepareLength();
	const auto kex_host_key_mark = s.Mark();
	host_key->SerializePublic(s);
	s.CommitLength(kex_host_key_length);
	const auto server_host_key_blob = s.Since(kex_host_key_mark);

	const auto server_ephemeral_public_key_length = s.PrepareLength();
	const auto server_ephemeral_public_key_mark = s.Mark();
	kex_algorithm->SerializeEphemeralPublicKey(s);
	const auto server_ephemeral_public_key = s.Since(server_ephemeral_public_key_mark);
	s.CommitLength(server_ephemeral_public_key_length);

	Serializer shared_secret;
	kex_algorithm->GenerateSharedSecret(client_ephemeral_public_key, shared_secret);
	const auto shared_secret_ = shared_secret.Finish();

	constexpr auto hash_alg = DigestAlgorithm::SHA256; // TODO

	const std::string_view client_version = peer_version;
	auto server_version = g_server_version;
	server_version.remove_suffix(2); // remove CR LF

	const std::span<const std::byte> client_kexinit = peer_kexinit;
	const std::span<const std::byte> server_kexinit = my_kexinit;

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
	kex_algorithm.reset();
}

inline void
Connection::SendNewKeys()
{
	SendPacket(PacketSerializer{MessageNumber::NEWKEYS});

	auto send_cipher = kex_state.MakeCipher(encryption_algorithms_server_to_client,
						mac_algorithms_server_to_client,
						Direction::OUTGOING);
	if (send_cipher == nullptr)
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"No client-to-server encryption algorithm"sv,
		};

	const bool was_encrypted = output.IsEncrypted();

	output.SetCipher(std::move(send_cipher));

	if (!was_encrypted && IsEncrypted())
		OnEncrypted();
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
	peer_kexinit = payload;

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

	kex_algorithm = MakeKex(kex_algorithms);
	if (!kex_algorithm)
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"No supported KEX algorithm"sv,
		};

	peer_wants_ext_info = StringListContains(kex_algorithms,
						 role == Role::SERVER ? "ext-info-c"sv : "ext-info-s"sv);

	if (StringListContains(kex_algorithms,
			       role == Role::SERVER ? "kex-strict-c-v00@openssh.com"sv : "kex-strict-s-v00@openssh.com"sv)) {
		peer_wants_strict_key_exchange = true;

		if (!first_packet_was_kexinit)
			throw Disconnect{
				DisconnectReasonCode::KEY_EXCHANGE_FAILED,
				"First packet was not KEXINIT"sv,
			};

		output.AutoResetSeq();
	}

	switch (role) {
	case Role::SERVER:
		std::tie(host_key, host_key_algorithm) = ChooseHostKey(server_host_key_algorithms);
		if (host_key == nullptr)
			throw Disconnect{
				DisconnectReasonCode::KEY_EXCHANGE_FAILED,
				"No supported host key"sv,
			};

		SendKexInit();
		break;

	case Role::CLIENT:
		SendECDHKexInit();
		break;
	}
}

inline void
Connection::HandleNewKeys(std::span<const std::byte> payload)
{
	(void)payload;

	auto cipher = kex_state.MakeCipher(encryption_algorithms_client_to_server,
					   mac_algorithms_client_to_server,
					   Direction::INCOMING);
	if (cipher == nullptr)
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"No client-to-server encryption algorithm"sv,
		};

	const bool was_encrypted = input.IsEncrypted();

	input.SetCipher(std::move(cipher));

	if (peer_wants_strict_key_exchange)
		input.ResetSeq();

	if (!was_encrypted && IsEncrypted())
		OnEncrypted();
}

inline void
Connection::HandleECDHKexInit(std::span<const std::byte> payload)
{
	if (role != Role::SERVER)
		throw Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"Unexpected packet"sv,
		};

	if (!IsPastKexInit() || !kex_algorithm)
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

inline void
Connection::HandleECDHKexInitReply(std::span<const std::byte> payload)
{
	if (role != Role::CLIENT)
		throw Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"Unexpected packet"sv,
		};

	if (!IsPastKexInit() || !kex_algorithm)
		throw Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"No KEXINIT"sv,
		};

	Deserializer d{payload};

	const auto server_host_key_blob = d.ReadLengthEncoded();
	const auto server_ephemeral_public_key = d.ReadLengthEncoded();
	const auto signature = d.ReadLengthEncoded();
	d.ExpectEnd();

	// TODO do we trust server_host_key_blob?

	Serializer client_ephemeral_public_key_;
	kex_algorithm->SerializeEphemeralPublicKey(client_ephemeral_public_key_);
	const auto client_ephemeral_public_key = client_ephemeral_public_key_.Finish();

	Serializer shared_secret;
	kex_algorithm->GenerateSharedSecret(server_ephemeral_public_key, shared_secret);
	const auto shared_secret_ = shared_secret.Finish();

	constexpr auto hash_alg = DigestAlgorithm::SHA256; // TODO

	auto client_version = g_server_version;
	client_version.remove_suffix(2); // remove CR LF

	const std::span<const std::byte> client_kexinit = my_kexinit;
	const std::span<const std::byte> server_kexinit = peer_kexinit;

	const std::string_view server_version = peer_version;

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

	kex_state.DeriveKeys(hash, shared_secret_, role, true);
	kex_algorithm.reset();

	SendNewKeys();

	if (peer_wants_ext_info && role == Role::SERVER)
		SendExtInfo();
}

static constexpr bool
IsAllowedKexMessage(MessageNumber msg, Role role) noexcept
{
	switch (msg) {
	case MessageNumber::DISCONNECT:
	case MessageNumber::NEWKEYS:
		return true;

	case MessageNumber::ECDH_KEX_INIT:
		return role == Role::SERVER;

	case MessageNumber::ECDH_KEX_INIT_REPLY:
		return role == Role::CLIENT;

	default:
		return false;
	}
}

void
Connection::HandlePacket(MessageNumber msg, std::span<const std::byte> payload)
{
	if (!input.IsEncrypted()) {
		if (!IsPastKexInit()) {
			/* this is the first packet */

			if (msg != MessageNumber::KEXINIT)
				first_packet_was_kexinit = false;
		} else if (peer_wants_strict_key_exchange &&
			   !IsAllowedKexMessage(msg, role)) {
			throw Disconnect{
				DisconnectReasonCode::KEY_EXCHANGE_FAILED,
				"Unexpected KEX packet"sv,
			};
		}
	}

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

	case MessageNumber::ECDH_KEX_INIT_REPLY:
		HandleECDHKexInitReply(payload);
		break;

	default:
		SendPacket(MakeUnimplemented(input.GetSeq()));
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

BufferedResult
Connection::OnBufferedData()
{
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

		peer_version.assign(s);

		version_exchanged = true;

		if (role == Role::CLIENT)
			SendKexInit();
	}

	if (!input.Feed(socket.GetInputBuffer()))
		return BufferedResult::DESTROYED;

	socket.GetInputBuffer().FreeIfEmpty();
	return socket.IsFull()
		? BufferedResult::OK
		: BufferedResult::MORE;
}

bool
Connection::OnBufferedWrite()
{
	OnWriteUnblocked();

	switch (output.Flush()) {
	case Output::FlushResult::DONE:
		socket.UnscheduleWrite();
		break;

	case Output::FlushResult::MORE:
		OnWriteBlocked();
		break;

	case Output::FlushResult::DESTROYED:
		return false;
	}

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

bool
Connection::OnInputReady() noexcept
try {
	while (true) {
		const auto payload = input.ReadPacket();
		if (payload.data() == nullptr) {
			socket.ScheduleRead();
			return true;
		}

		HandleRawPacket(payload);
		input.ConsumePacket();
	}

	socket.ScheduleRead();
	return true;
} catch (const Disconnect &d) {
	DoDisconnect(d.reason_code, d.msg);
	return false;
} catch (const Destroyed &) {
	return false;
} catch (...) {
	OnBufferedError(std::current_exception());
	return false;
}

} // namespace SSH
