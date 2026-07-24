// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "Connection.hxx"
#include "Disposer.hxx"
#include "IdentificationString.hxx"
#include "Input.hxx"
#include "Output.hxx"
#include "Metrics.hxx"
#include "KexInterface.hxx"
#include "KexFactory.hxx"
#include "KexHash.hxx"
#include "KexSignature.hxx"
#include "KexProposal.hxx"
#include "KexStrings.hxx"
#include "HostKeyChooser.hxx"
#include "HostKeyVerifier.hxx"
#include "Handler.hxx"
#include "Sizes.hxx"
#include "StringList.hxx"
#include "Protocol.hxx"
#include "Serializer.hxx"
#include "MakePacket.hxx"
#include "ParsePacket.hxx"
#include "key/Key.hxx"
#include "key/Algorithms.hxx"
#include "cipher/Cipher.hxx"
#include "cipher/Factory.hxx"
#include "thread/Pool.hxx"
#include "system/Urandom.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "net/SocketError.hxx"
#include "net/SocketProtocolError.hxx"
#include "util/SpanCast.hxx"
#include "Digest.hxx"

using std::string_view_literals::operator""sv;

namespace SSH {

struct Connection::HandlerHookTraits : IntrusiveListMemberHookTraits<&ConnectionHandler::connection_handler_siblings> {};

static void
SerializeKex(Serializer &s, std::span<const std::byte, KEX_COOKIE_SIZE> cookie,
	     const KexProposal &proposal, bool first_kex_packet_follows=false)
{
	s.WriteN(cookie);
	SerializeProposal(s, proposal);
	s.WriteBool(first_kex_packet_follows);
	s.WriteU32(0); // reserved
}

Connection::Connection(EventLoop &event_loop, UniqueSocketDescriptor &&_fd,
		       ConnectionDisposer &_disposer,
		       Role _role,
		       const HostKeyChooser *_host_key_chooser,
		       const HostKeyVerifier *_host_key_verifier)
	:disposer(_disposer),
	 host_key_chooser(_host_key_chooser),
	 host_key_verifier(_host_key_verifier),
	 socket(event_loop),
	 input(*new Input(thread_pool_get_queue(event_loop), *this)),
	 output(*new Output(thread_pool_get_queue(event_loop), socket)),
	 rekey_timer(event_loop, BIND_THIS_METHOD(OnRekeyTimer)),
	 role(_role)
{
	socket.Init(_fd.Release(), FD_TCP,
		    std::chrono::seconds(30),
		    *this);
	socket.ScheduleRead();

	if (socket.DirectWrite(AsBytes(IDENTIFICATION_STRING)) < 0)
		throw MakeSocketError("Failed to send VersionExchange");
}

Connection::~Connection() noexcept
{
	output.Destroy();
	input.Destroy();
}

void
Connection::AddHandler(ConnectionHandler &handler) noexcept
{
	assert(!IsDead());

	handlers.push_front(handler);
}

bool
Connection::IsEncrypted() const noexcept
{
	return input.IsEncrypted() && output.IsEncrypted();
}

inline bool
Connection::IsRekeying() const noexcept
{
	return output.IsEncrypted() &&
		kex_flags.kexinit_sent && !kex_flags.newkeys_sent;
}

void
Connection::SetAuthenticated() noexcept
{
	assert(!IsDead());
	assert(IsEncrypted());
	assert(!authenticated);

	authenticated = true;

	/* enable periodic rekeying */
	rekey_timer.Schedule(REKEY_INTERVAL);
}

inline void
Connection::InitiateRekey()
{
	assert(IsEncrypted());
	assert(authenticated);
	assert(!IsDead());

	if (!kex_flags.IsIdle())
		return;

	SendKexInit();
}

inline void
Connection::OnRekeyTimer() noexcept
try {
	InitiateRekey();
} catch (...) {
	CloseError(std::current_exception());
}

inline void
Connection::SendPacket(std::span<const std::byte> src) noexcept
{
	assert(!IsDead());

	if (metrics != nullptr) {
		++metrics->packets_sent;

		// TODO count the number of raw bytes actually sent on the wire
		metrics->bytes_sent += src.size();
	}

	output.Push(src);
	socket.DeferWrite();

	if (const auto *cipher = output.GetCipher(); cipher != nullptr) {
		encrypted_bytes_since_kex += src.size() + cipher->GetAuthSize();

		if (authenticated &&
		    encrypted_bytes_since_kex >= REKEY_BYTES &&
		    kex_flags.IsIdle())
			/* rekey now */
			rekey_timer.Schedule(Event::Duration::zero());
	}
}

void
Connection::SendPacket(PacketSerializer &&s) noexcept
{
	const auto *send_cipher = output.GetCipher();
	SendPacket(s.Finish(send_cipher
			    != nullptr ? send_cipher->GetBlockSize() : 8,
			    send_cipher != nullptr &&
			    send_cipher->IsHeaderExcludedFromPadding()));
}

void
Connection::SendPacket(MessageNumber msg, std::span<const std::byte> payload)
{
	SSH::PacketSerializer s{msg};
	s.WriteN(payload);
	SendPacket(std::move(s));
}

void
Connection::DoDisconnect(DisconnectReasonCode reason_code, std::string_view msg) noexcept
{
	if (IsDead())
		return;

	OnDisconnecting(reason_code, msg);

	SendPacket(MakeDisconnect(reason_code, msg));

	if (output.IsEncrypted()) {
		/* we have to wait for the worker thread to encrypt
		   the DISCONNECT packet before we can actually send
		   it to the socket; therefore postpone the Destroy()
		   call */
		dead = true;

		rekey_timer.Cancel();

		/* we now have very little patience with this
                   client */
		socket.SetWriteTimeout(std::chrono::seconds{1});

		/* we don't want to receive anything from it */
		socket.UnscheduleOnlyRead();
		return;
	}

	try {
		/* attempt to flush the DISCONNECT packet immediately
		   before we close the socket */
		switch (output.Flush()) {
		case Output::FlushResult::DONE:
		case Output::FlushResult::MORE:
			break;

		case Output::FlushResult::DESTROYED:
			return;
		}
	} catch (...) {
		/* ignore errors, we're going to disconnect anyway */
	}

	disposer.Dispose(this);
}

void
Connection::OnWriteBlocked() noexcept
{
	for (auto &i : handlers)
		i.OnWriteBlocked();
}

void
Connection::OnWriteUnblocked() noexcept
{
	for (auto &i : handlers)
		i.OnWriteUnblocked();
}

void
Connection::OnDisconnecting([[maybe_unused]] DisconnectReasonCode reason_code,
			    [[maybe_unused]] std::string_view msg) noexcept
{
	for (auto &i : handlers)
		i.OnDisconnecting();
}

void
Connection::OnDisconnected([[maybe_unused]] DisconnectReasonCode reason_code,
			   [[maybe_unused]] std::string_view msg) noexcept
{
}

inline void
Connection::SendKexInit()
{
	assert(!kex_flags.kexinit_sent);
	assert(!kex_flags.newkeys_sent);
	assert(!kex_flags.newkeys_received);

	PacketSerializer s{MessageNumber::KEXINIT};

	const KexProposal proposal{
		.kex_algorithms = role == Role::SERVER ? all_server_kex_algorithms : all_client_kex_algorithms,
		.server_host_key_algorithms = host_key_chooser ? host_key_chooser->GetServerHostKeyAlgorithms() : all_public_key_algorithms,
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

	kex_flags.kexinit_sent = true;

	if (IsRekeying() && !write_blocked)
		OnWriteBlocked();

	SendPacket(std::move(s));
}

inline void
Connection::SendECDHKexInit()
{
	assert(role == Role::CLIENT);
	assert(kex_flags.kexinit_sent);
	assert(kex_flags.kexinit_received);
	assert(!kex_flags.newkeys_sent);
	assert(!kex_flags.newkeys_received);
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
	assert(kex_flags.kexinit_sent);
	assert(kex_flags.kexinit_received);
	assert(!kex_flags.newkeys_sent);
	assert(!kex_flags.newkeys_received);
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
	auto server_version = IDENTIFICATION_STRING;
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

	const bool initial_kex = kex_state.session_id.empty();
	kex_state.DeriveKeys(hash, shared_secret_, role, initial_kex);
	kex_algorithm.reset();
}

inline void
Connection::SendNewKeys()
{
	assert(kex_flags.kexinit_sent);
	assert(kex_flags.kexinit_received);
	assert(!kex_flags.newkeys_sent);
	assert(!kex_flags.newkeys_received);

	const bool was_rekeying = IsRekeying();

	rekey_timer.Cancel();

	SendPacket(PacketSerializer{MessageNumber::NEWKEYS});
	kex_flags.newkeys_sent = true;

	const auto send_encryption_algorithm =
		FindNegotiatedAlgorithm(role, Direction::OUTGOING,
					all_encryption_algorithms,
					encryption_algorithms_client_to_server,
					encryption_algorithms_server_to_client);
	const auto send_mac_algorithm =
		FindNegotiatedAlgorithm(role, Direction::OUTGOING,
					all_mac_algorithms,
					mac_algorithms_client_to_server,
					mac_algorithms_server_to_client);

	auto send_cipher = kex_state.MakeCipher(send_encryption_algorithm,
						send_mac_algorithm,
						Direction::OUTGOING);
	if (send_cipher == nullptr)
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"No outgoing encryption algorithm"sv,
		};

	const bool was_encrypted = output.IsEncrypted();

	output.SetCipher(std::move(send_cipher));
	encrypted_bytes_since_kex = 0;

	if (kex_flags.ResetIfComplete())
		rekey_timer.Schedule(REKEY_INTERVAL);

	if (!was_encrypted && IsEncrypted())
		OnEncrypted();

	if (was_rekeying && !write_blocked)
		OnWriteUnblocked();
}

inline void
Connection::SendExtInfo()
{
	PacketSerializer s{MessageNumber::EXT_INFO};
	s.WriteU32(2);

	/* sending this works around a OpenSSH client bug which causes
	   it to ignore RSA keys; without EXT_INFO,
	   key_sig_algorithm() skips all RSA keys unless "ssh-rsa"
	   (RSA with SHA-1) is explicitly added to option
	   "PubkeyAcceptedAlgorithms", even though we want to use
	   "rsa-sha2-*" */
	s.WriteString("server-sig-algs"sv);
	s.WriteString(all_public_key_algorithms);

	s.WriteString("agent-forward"sv);
	s.WriteString("0"sv);

	SendPacket(std::move(s));
}

inline void
Connection::HandleDisconnect(std::span<const std::byte> payload)
{
	const auto p = ParseDisconnect(payload);
	OnDisconnected(p.reason_code, p.description);

	disposer.Dispose(this);
	throw Destroyed{};
}

inline void
Connection::HandleKexInit(std::span<const std::byte> payload)
{
	rekey_timer.Cancel();

	const bool initial_kex = !IsEncrypted();

	if (kex_flags.kexinit_received ||
	    kex_flags.newkeys_sent ||
	    kex_flags.newkeys_received)
		throw Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"Unexpected KEXINIT"sv,
		};

	const auto p = ParseKexInit(payload);

	kex_flags.kexinit_received = true;
	peer_kexinit = payload;

	encryption_algorithms_client_to_server = p.encryption_algorithms_client_to_server;
	encryption_algorithms_server_to_client = p.encryption_algorithms_server_to_client;
	mac_algorithms_client_to_server = p.mac_algorithms_client_to_server;
	mac_algorithms_server_to_client = p.mac_algorithms_server_to_client;

	const auto negotiated_kex_algorithm = role == Role::SERVER
		? FindCommonAlgorithm(p.kex_algorithms, all_server_kex_algorithms)
		: FindCommonAlgorithm(all_client_kex_algorithms, p.kex_algorithms);

	kex_algorithm = MakeKex(negotiated_kex_algorithm);
	if (!kex_algorithm)
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"No supported KEX algorithm"sv,
		};

	peer_wants_ext_info = StringListContains(p.kex_algorithms,
						 role == Role::SERVER ? "ext-info-c"sv : "ext-info-s"sv);

	if (initial_kex)
		/* kex-strict is only supposed to be passed in the
		   initial KEX */
		peer_wants_strict_key_exchange =
			StringListContains(p.kex_algorithms,
					   role == Role::SERVER ? "kex-strict-c-v00@openssh.com"sv : "kex-strict-s-v00@openssh.com"sv);

	if (peer_wants_strict_key_exchange) {
		if (!first_packet_was_kexinit)
			throw Disconnect{
				DisconnectReasonCode::KEY_EXCHANGE_FAILED,
				"First packet was not KEXINIT"sv,
			};

		input.AutoResetSeq();
		output.AutoResetSeq();
	}

	switch (role) {
	case Role::SERVER:
		assert(host_key_chooser != nullptr);

		std::tie(host_key, host_key_algorithm) = host_key_chooser->ChooseHostKey(p.server_host_key_algorithms);
		if (host_key == nullptr)
			throw Disconnect{
				DisconnectReasonCode::KEY_EXCHANGE_FAILED,
				"No supported host key"sv,
			};

		if (!kex_flags.kexinit_sent)
			SendKexInit();

		ignore_next_kex_packet = p.first_kex_packet_follows &&
			(FirstStringListItem(p.kex_algorithms) != negotiated_kex_algorithm ||
			 FirstStringListItem(p.server_host_key_algorithms) != host_key_algorithm);

		break;

	case Role::CLIENT:
		if (!kex_flags.kexinit_sent)
			SendKexInit();

		SendECDHKexInit();
		break;
	}
}

inline void
Connection::HandleNewKeys(std::span<const std::byte> payload)
{
	(void)payload;

	rekey_timer.Cancel();

	if (!kex_flags.kexinit_sent ||
	    !kex_flags.kexinit_received ||
	    !kex_flags.newkeys_sent ||
	    kex_flags.newkeys_received)
		throw Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"Unexpected NEWKEYS"sv,
		};

	kex_flags.newkeys_received = true;

	if (kex_state.session_id.empty())
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"No session id"sv,
		};

	const auto receive_encryption_algorithm =
		FindNegotiatedAlgorithm(role, Direction::INCOMING,
				       all_encryption_algorithms,
				       encryption_algorithms_client_to_server,
				       encryption_algorithms_server_to_client);
	const auto receive_mac_algorithm =
		FindNegotiatedAlgorithm(role, Direction::INCOMING,
				       all_mac_algorithms,
				       mac_algorithms_client_to_server,
				       mac_algorithms_server_to_client);

	auto cipher = kex_state.MakeCipher(receive_encryption_algorithm,
					   receive_mac_algorithm,
					   Direction::INCOMING);
	if (cipher == nullptr)
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"No incoming encryption algorithm"sv,
		};

	const bool was_encrypted = input.IsEncrypted();

	input.SetCipher(std::move(cipher));

	if (kex_flags.ResetIfComplete())
		rekey_timer.Schedule(REKEY_INTERVAL);

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

	if (!kex_flags.kexinit_sent ||
	    !kex_flags.kexinit_received ||
	    kex_flags.newkeys_sent ||
	    kex_flags.newkeys_received ||
	    !kex_algorithm)
		throw Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"No KEXINIT"sv,
		};

	const auto p = ParseECDHKexInit(payload);

	SendECDHKexInitReply(p.client_ephemeral_public_key);
	SendNewKeys();

	if (peer_wants_ext_info)
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

	if (!kex_flags.kexinit_sent ||
	    !kex_flags.kexinit_received ||
	    kex_flags.newkeys_sent ||
	    kex_flags.newkeys_received ||
	    !kex_algorithm)
		throw Disconnect{
			DisconnectReasonCode::PROTOCOL_ERROR,
			"No KEXINIT"sv,
		};

	const auto p = ParseECDHKexInitReply(payload);

	if (host_key_verifier == nullptr ||
	    !host_key_verifier->VerifyHostKey(p.server_host_key_blob))
		throw Disconnect{
			DisconnectReasonCode::HOST_KEY_NOT_VERIFIABLE,
			"Host key not accepted"sv,
		};

	Serializer client_ephemeral_public_key_;
	kex_algorithm->SerializeEphemeralPublicKey(client_ephemeral_public_key_);
	const auto client_ephemeral_public_key = client_ephemeral_public_key_.Finish();

	Serializer shared_secret;
	kex_algorithm->GenerateSharedSecret(p.server_ephemeral_public_key, shared_secret);
	const auto shared_secret_ = shared_secret.Finish();

	constexpr auto hash_alg = DigestAlgorithm::SHA256; // TODO

	auto client_version = IDENTIFICATION_STRING;
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
					 p.server_host_key_blob,
					 client_ephemeral_public_key,
					 p.server_ephemeral_public_key,
					 shared_secret_,
					 hash_buffer);

	const auto hash = std::span{hash_buffer}.first(hashlen);

	bool valid_signature;
	try {
		valid_signature = VerifyKexSignature(p.server_host_key_blob, hash, p.signature);
	} catch (...) {
		valid_signature = false;
	}

	if (!valid_signature)
		throw Disconnect{
			DisconnectReasonCode::KEY_EXCHANGE_FAILED,
			"Bad host key signature"sv,
		};

	const bool initial_kex = kex_state.session_id.empty();
	kex_state.DeriveKeys(hash, shared_secret_, role, initial_kex);
	kex_algorithm.reset();

	SendNewKeys();
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
		if (!kex_flags.kexinit_received) {
			/* this is the first packet */

			if (msg != MessageNumber::KEXINIT)
				first_packet_was_kexinit = false;
		} else if (ignore_next_kex_packet) {
			// TODO obey ignore_next_kex_packet while rekeying, too
			ignore_next_kex_packet = false;

			if (IsKex(msg))
				return;
		} else if (peer_wants_strict_key_exchange &&
			   !IsAllowedKexMessage(msg, role)) {
			throw Disconnect{
				DisconnectReasonCode::KEY_EXCHANGE_FAILED,
				"Unexpected KEX packet"sv,
			};
		}
	}

	for (auto &i : handlers)
		if (i.HandlePacket(msg, payload))
			return;

	switch (msg) {
	case MessageNumber::DISCONNECT:
		HandleDisconnect(payload);

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

bool
Connection::OnBufferedHangup() noexcept
{
	if (IsDead()) {
		/* don't bother flushing the pending DISCONNECT packet
		   if the peer has already hung up */
		disposer.Dispose(this);
		return false;
	}

	return true;
}

BufferedResult
Connection::OnBufferedData()
{
	if (!version_exchanged) {
		const auto r = std::as_bytes(socket.ReadBuffer());
		const auto eol = std::find(r.begin(), r.end(), std::byte{'\n'});
		if (eol == r.end()) {
			if (r.size() >= 255) {
				disposer.Dispose(this);
				return BufferedResult::DESTROYED;
			}

			return BufferedResult::MORE;
		}

		const std::size_t length = std::distance(r.begin(), eol);
		auto s = ToStringView(r.first(length));
		socket.KeepConsumed(length + 1);

		if (!s.starts_with("SSH-"sv)) {
			disposer.Dispose(this);
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
	const bool was_write_blocked = write_blocked;
	write_blocked = false;
	if (was_write_blocked && !IsRekeying())
		OnWriteUnblocked();

	switch (output.Flush()) {
	case Output::FlushResult::DONE:
		if (IsDead() && output.IsEmpty()) {
			disposer.Dispose(this);
			return false;
		}

		socket.UnscheduleWrite();
		break;

	case Output::FlushResult::MORE:
		socket.ScheduleWrite();

		write_blocked = true;
		if (!IsRekeying())
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
	disposer.Dispose(this);
	return false;
}

void
Connection::OnBufferedError([[maybe_unused]] std::exception_ptr e) noexcept
{
	disposer.Dispose(this);
}

bool
Connection::OnInputReady() noexcept
try {
	if (IsDead())
		return false;

	while (true) {
		const auto payload = input.ReadPacket();
		if (payload.data() == nullptr)
			break;

		if (metrics != nullptr) {
			++metrics->packets_received;

			// TODO count the number of raw bytes actually received on the wire
			metrics->bytes_received += payload.size();
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
	CloseError(std::current_exception());
	return false;
}

} // namespace SSH
