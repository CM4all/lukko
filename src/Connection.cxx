// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Connection.hxx"
#include "Instance.hxx"
#include "Listener.hxx"
#include "SessionChannel.hxx"
#include "SocketChannel.hxx"
#include "RConnect.hxx"
#include "DelegateOpen.hxx"
#include "DebugMode.hxx"
#include "key/Parser.hxx"
#include "key/Key.hxx"
#include "key/TextFile.hxx"
#include "key/Fingerprint.hxx"
#include "ssh/Protocol.hxx"
#include "ssh/MakePacket.hxx"
#include "ssh/Deserializer.hxx"
#include "ssh/Channel.hxx"
#include "lib/fmt/SocketAddressFormatter.hxx"
#include "spawn/Prepared.hxx"
#include "net/StaticSocketAddress.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "io/Beneath.hxx"
#include "io/FileAt.hxx"
#include "io/UniqueFileDescriptor.hxx"
#include "co/InvokeTask.hxx"
#include "co/Task.hxx"
#include "co/Sleep.hxx"
#include "util/AllocatedArray.hxx"
#include "util/Cancellable.hxx"
#include "util/CharUtil.hxx"
#include "util/Exception.hxx" // for GetFullMessage()
#include "util/StringAPI.hxx"
#include "util/StringVerify.hxx"

#ifdef ENABLE_TRANSLATION
#include "translation/LoginGlue.hxx"
#include "translation/Response.hxx"
#include "AllocatorPtr.hxx"
#endif // ENABLE_TRANSLATION

#include <fmt/core.h>

#include <fcntl.h> // for O_*
#include <pwd.h>

using std::string_view_literals::operator""sv;

#ifdef ENABLE_TRANSLATION

struct Connection::Translation {
	Allocator alloc;
	TranslateResponse response;

	Translation(Allocator &&_alloc,
		    TranslateResponse &&_response) noexcept
		:alloc(std::move(_alloc)),
		 response(std::move(_response)) {}
};

#endif // ENABLE_TRANSLATION

Connection::Connection(Instance &_instance, Listener &_listener,
		       UniqueSocketDescriptor _fd, SocketAddress _peer_address,
		       const SecretKeyList &_host_keys)
	:SSH::CConnection(_instance.GetEventLoop(), std::move(_fd),
			  SSH::Role::SERVER,
			  _host_keys),
	 instance(_instance), listener(_listener),
	 peer_address(_peer_address),
	 local_address(GetSocket().GetLocalAddress()),
	 logger(instance.GetLogger())
{
}

Connection::~Connection() noexcept = default;

SpawnService &
Connection::GetSpawnService() const noexcept
{
	return instance.GetSpawnService();
}

#ifdef ENABLE_TRANSLATION

const TranslateResponse *
Connection::GetTranslationResponse() const noexcept
{
	return translation
		? &translation->response
		: nullptr;
}

#endif

bool
Connection::IsSftpOnly() const noexcept
{
	assert(IsAuthenticated());

#ifdef ENABLE_TRANSLATION
	if (translation && translation->response.token != nullptr &&
	    StringIsEqual(translation->response.token, "sftp-only"))
		return true;
#endif

	return false;
}

bool
Connection::IsForwardingAllowed() const noexcept
{
	if (IsSftpOnly())
		return false;

#ifdef ENABLE_TRANSLATION
	if (translation &&
	    translation->response.child_options.ns.enable_network)
		/* if the user is supposed to run in an isolated
		   network namespace, refuse to open TCP connections
		   anywhere */
		return false;
#endif

	return true;
}

inline const char *
Connection::GetHome() const noexcept
{
#ifdef ENABLE_TRANSLATION
	if (translation)
		return translation->response.child_options.ns.mount.home;
#endif // ENABLE_TRANSLATION

	if (!home_path.empty())
		return home_path.c_str();

	return nullptr;
}

UniqueFileDescriptor
Connection::OpenHome() const noexcept
{
	UniqueFileDescriptor fd;

	if (const char *home = GetHome())
		fd.Open(home, O_PATH|O_DIRECTORY);

	return fd;
}

UniqueFileDescriptor
Connection::OpenInHome(const char *path) const noexcept
{
	if (auto home = OpenHome(); home.IsDefined()) {
		if (auto fd = TryOpenReadOnlyBeneath({home, path});
		    fd.IsDefined())
			return fd;
		else if (errno != EACCES)
			return {};
	}

	/* the plain open failed with EACCES; try again while
	   impersonating the target user */

	try {
		return DelegateOpen(*this, path);
	} catch (...) {
		// TODO log error?
	}

	return {};
}

const char *
Connection::GetShell() const noexcept
{
#ifdef ENABLE_TRANSLATION
	if (translation && translation->response.shell != nullptr)
		return translation->response.shell;
#endif // ENABLE_TRANSLATION

	if (!shell.empty())
		return shell.c_str();

	return "/bin/sh";
}

void
Connection::PrepareChildProcess(PreparedChildProcess &p) const noexcept
{
#ifdef ENABLE_TRANSLATION
	if (translation) {
		translation->response.child_options.CopyTo(p);
	} else {
#endif // ENABLE_TRANSLATION
		p.uid_gid.uid = uid;
		p.uid_gid.gid = gid;

		if (!home_path.empty())
			p.ns.mount.home = home_path.c_str();
#ifdef ENABLE_TRANSLATION
	}
#endif // ENABLE_TRANSLATION
}

inline bool
Connection::IsAcceptedPublicKey(std::span<const std::byte> public_key_blob) noexcept
{
#ifdef ENABLE_TRANSLATION
	if (translation && translation->response.authorized_keys != nullptr) {
		if (auto options =
		    PublicKeysTextFileContains(translation->response.authorized_keys,
					       public_key_blob)) {
			authorized_key_options = std::move(*options);
			return true;
		}
	}
#endif // ENABLE_TRANSLATION

	if (const auto *options = instance.GetGlobalAuthorizedKeys().Find(public_key_blob)) {
		authorized_key_options = *options;
		return true;
	}

	if (auto fd = OpenInHome(".ssh/authorized_keys"); fd.IsDefined()) {
		if (auto options = PublicKeysTextFileContains(fd, public_key_blob)) {
			authorized_key_options = std::move(*options);
			return true;
		}
	}

	return false;
}

inline bool
Connection::IsAcceptedHostPublicKey(std::span<const std::byte> public_key_blob) noexcept
{
	// TODO
	(void)public_key_blob;
	return true;
}

class ResolveSocketChannelOperation final : Cancellable {
	Connection &connection;
	const SSH::ChannelInit init;
	Co::InvokeTask invoke_task;
	UniqueSocketDescriptor socket;

public:
	ResolveSocketChannelOperation(Connection &_connection,
				      SSH::ChannelInit _init) noexcept
		:connection(_connection), init(_init) {}

	void Start(std::string_view host, unsigned port,
		   CancellablePointer &caller_cancel_ptr) noexcept {
		caller_cancel_ptr = *this;
		invoke_task = Start(host, port);
		invoke_task.Start(BIND_THIS_METHOD(OnCompletion));
	}

private:
	Co::InvokeTask Start(std::string_view host, unsigned port) {
		socket = co_await ResolveConnectTCP(connection, host, port);
	}

	void OnCompletion(std::exception_ptr error) noexcept {
		if (error) {
			// TODO log error?
			connection.AsyncChannelOpenFailure(init,
							   SSH::ChannelOpenFailureReasonCode::CONNECT_FAILED,
							   GetFullMessage(error));
			delete this;
		} else {
			auto &_connection = connection;
			auto *channel = new SocketChannel(_connection, init, std::move(socket));
			delete this;
			_connection.AsyncChannelOpenSuccess(*channel);
		}
	}

	// virtual methods from class Cancellable
	virtual void Cancel() noexcept override {
		delete this;
	}
};

std::unique_ptr<SSH::Channel>
Connection::OpenChannel(std::string_view channel_type,
			SSH::ChannelInit init,
			std::span<const std::byte> payload,
			CancellablePointer &cancel_ptr)
{
	fmt::print(stderr, "ChannelOpen type={} local_channel={} peer_channel={}\n",
		   channel_type, init.local_channel, init.peer_channel);

	if (channel_type == "session"sv) {
		CConnection &connection = *this;
		return std::make_unique<SessionChannel>(connection, init);
	} else if (channel_type == "direct-tcpip"sv) {
		if (!IsForwardingAllowed()) {
			throw ChannelOpenFailure{
				SSH::ChannelOpenFailureReasonCode::ADMINISTRATIVELY_PROHIBITED,
				"TCP forwarding not allowed",
			};
		}

		SSH::Deserializer d{payload};
		const auto connect_host = d.ReadString();
		const auto connect_port = d.ReadU32();
		const auto originator_ip = d.ReadString();
		const auto originator_port = d.ReadU32();
		d.ExpectEnd();

		fmt::print(stderr, "  connect=[{}]:{} originator=[{}]:{}\n",
			   connect_host, connect_port,
			   originator_ip, originator_port);

		auto *operation = new ResolveSocketChannelOperation(*this, init);
		operation->Start(connect_host, connect_port, cancel_ptr);
		return {};
	} else
		return SSH::CConnection::OpenChannel(channel_type, init, payload,
						     cancel_ptr);
}

inline void
Connection::HandleServiceRequest(std::span<const std::byte> payload)
{
	SSH::Deserializer d{payload};
	const auto service = d.ReadString();
	d.ExpectEnd();

	fmt::print(stderr, "ServiceRequest '{}'\n", service);

	if (service == "ssh-userauth"sv) {
		SendPacket(SSH::MakeServiceAccept(service));
	} else
		throw Disconnect{SSH::DisconnectReasonCode::SERVICE_NOT_AVAILABLE,
			"Unsupported service"sv};
}

static bool
IsValidUsername(std::string_view username) noexcept
{
	return username.size() <= 255 && CheckCharsNonEmpty(username, [](char ch){
		return IsAlphaNumericASCII(ch) || ch == '-' || ch == '_';
	});
}

inline Co::InvokeTask
Connection::CoHandleUserauthRequest(AllocatedArray<std::byte> payload)
{
	assert(!IsAuthenticated());

	/* this object aims to prevent timing-based guesses by
	   delaying all error responses until 100ms have elapsed since
	   the USERAUTH_REQUEST was received */
	Co::LazySleep fail_sleep{GetEventLoop(), std::chrono::milliseconds{100}};

	SSH::Deserializer d{payload};
	const auto to_be_signed_marker = d.Mark();
	const auto new_username = d.ReadString();
	const auto service_name = d.ReadString();
	const auto method_name = d.ReadString();

	fmt::print(stderr, "Userauth '{}' service='{}' method='{}'\n",
		   new_username, service_name, method_name);

	if (service_name != "ssh-connection"sv) {
		SendPacket(SSH::MakeUserauthFailure({}, false));
		co_return;
	}

	if (!IsValidUsername(new_username))
		throw Disconnect{
			SSH::DisconnectReasonCode::ILLEGAL_USER_NAME,
			"Illegal user name"sv,
		};

	std::string_view auth_methods = "publickey,hostbased"sv;

#ifdef ENABLE_TRANSLATION
	bool password_accepted = false;

	if (const char *translation_server = instance.GetTranslationServer()) {
		auth_methods = "publickey,hostbased,password"sv;

		std::string_view password{};
		if (method_name == "password"sv) {
			const bool change_password = d.ReadBool();
			password = d.ReadString();
			d.ExpectEnd();

			if (change_password) {
				/* password change not implemented */
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				co_return;
			}

			if (password.empty()) {
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				co_return;
			}
		}

		Allocator alloc;
		auto response = co_await
			TranslateLogin(GetEventLoop(), alloc, translation_server,
				       "ssh"sv, listener.GetTag(),
				       new_username, password);

		if (response.status != HttpStatus{}) {
			co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure({}, false));
			co_return;
		}

		translation = std::make_unique<Translation>(std::move(alloc),
							    std::move(response));
		password_accepted = !password.empty();
	} else
#endif // ENABLE_TRANSLATION
	{
		const auto *pw = getpwnam(std::string{new_username}.c_str());
		if (pw == nullptr) {
			co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			co_return;
		}

		// TODO extended groups?
		uid = pw->pw_uid;
		gid = pw->pw_gid;
		home_path = pw->pw_dir;
		shell = pw->pw_shell;
	}

	if (method_name == "publickey"sv) {
		const bool with_signature = d.ReadBool();
		const auto public_key_algorithm = d.ReadString();
		const auto public_key_blob = d.ReadLengthEncoded();

		fmt::print(stderr, "  public_key_algorithm='{}'\n",
			   public_key_algorithm);

		if (!IsAcceptedPublicKey(public_key_blob)) {
			co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			co_return;
		}

		std::unique_ptr<PublicKey> public_key;

		try {
			public_key = ParsePublicKeyBlob(public_key_blob);
		} catch (...) {
			logger(1, "Failed to parse the client's public key: ",
			       std::current_exception());
			// TODO co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			co_return;
		}

		if (!with_signature) {
			d.ExpectEnd();

			SendPacket(SSH::MakeUserauthPkOk(public_key_algorithm,
							 public_key_blob));
			co_return;
		} else {
			const auto to_be_signed = d.Since(to_be_signed_marker);
			const auto signature = d.ReadLengthEncoded();
			d.ExpectEnd();

			try {
				SSH::Serializer s;
				s.WriteLengthEncoded(GetSessionId());
				s.WriteU8(static_cast<uint_least8_t>(SSH::MessageNumber::USERAUTH_REQUEST));
				s.WriteN(to_be_signed);

				if (!public_key->Verify(s.Finish(), signature)) {
					co_await fail_sleep;
					SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
					co_return;
				}
			} catch (...) {
				logger(1, "Failed to verify the client's public key: ",
				       std::current_exception());
				// TODO co_await fail_sleep;
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				co_return;
			}
		}

		fmt::print(stderr, "Accepted publickey for {} from {}: {} {}\n",
			   new_username, peer_address,
			   public_key->GetType(), GetFingerprint(*public_key));
	} else if (method_name == "hostbased"sv) {
		// TODO only allow if explicitly enabled

		const auto public_key_algorithm = d.ReadString();
		const auto public_key_blob = d.ReadLengthEncoded();
		const auto client_host_name = d.ReadString();
		const auto client_user_name = d.ReadString();
		const auto to_be_signed = d.Since(to_be_signed_marker);
		const auto signature = d.ReadLengthEncoded();
		d.ExpectEnd();

		fmt::print(stderr, "  hostbased public_key_algorithm='{}' client_host_name='{}' client_user_name='{}'\n",
			   public_key_algorithm, client_host_name, client_user_name);

		if (!IsAcceptedHostPublicKey(public_key_blob)) {
			co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			co_return;
		}

		std::unique_ptr<PublicKey> public_key;

		try {
			public_key = ParsePublicKeyBlob(public_key_blob);
		} catch (...) {
			logger(1, "Failed to parse the client's host public key: ",
			       std::current_exception());
			// TODO co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			co_return;
		}

		try {
			SSH::Serializer s;
			s.WriteLengthEncoded(GetSessionId());
			s.WriteU8(static_cast<uint_least8_t>(SSH::MessageNumber::USERAUTH_REQUEST));
			s.WriteN(to_be_signed);

			if (!public_key->Verify(s.Finish(), signature)) {
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				co_return;
			}
		} catch (...) {
			logger(1, "Failed to verify the client's public key: ",
			       std::current_exception());
			// TODO co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			co_return;
		}

		fmt::print(stderr, "Accepted hostkey for {} from {}: {} {}\n",
			   new_username, peer_address,
			   public_key->GetType(), GetFingerprint(*public_key));
#ifdef ENABLE_TRANSLATION
	} else if (password_accepted) {
		/* the password was successfully verified by the
		   translation server */
		fmt::print(stderr, "Accepted password for {} from {}\n",
			   new_username, peer_address);
#endif // ENABLE_TRANSLATION
	} else {
		co_await fail_sleep;
		SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
		co_return;
	}

	username.assign(new_username);

	SetAuthenticated();
	SendPacket(SSH::PacketSerializer{SSH::MessageNumber::USERAUTH_SUCCESS});
}

inline void
Connection::OnUserauthCompletion(std::exception_ptr error) noexcept
{
	if (error) {
		try {
			std::rethrow_exception(error);
		} catch (const Disconnect &d) {
			DoDisconnect(d.reason_code, d.msg);
		} catch (...) {
			OnBufferedError(std::move(error));
		}
	}
}

inline void
Connection::HandleUserauthRequest(std::span<const std::byte> payload)
{
	assert(!occupied_task);

	if (IsAuthenticated())
		/* RFC 4252 section 5.1: "When
		   SSH_MSG_USERAUTH_SUCCESS has been sent, any further
		   authentication requests received after that SHOULD
		   be silently ignored" */
		return;

	/* the payload is owned by the caller, therefore we need to
	   duplicate it into an AllocatedArray onwed by the coroutine,
	   so the coroutine can keep using it after this method
	   returns */
	occupied_task = CoHandleUserauthRequest(AllocatedArray{payload});
	occupied_task.Start(BIND_THIS_METHOD(OnUserauthCompletion));
}

/**
 * Is this message allowed while the connection is "occupied"?
 */
static constexpr bool
IsAllowedWhileOccupied(SSH::MessageNumber msg) noexcept
{
	switch (msg) {
	case SSH::MessageNumber::DISCONNECT:
	case SSH::MessageNumber::IGNORE:
	case SSH::MessageNumber::NEWCOMPRESS:
	case SSH::MessageNumber::KEXINIT:
	case SSH::MessageNumber::NEWKEYS:
	case SSH::MessageNumber::ECDH_KEX_INIT:
	case SSH::MessageNumber::ECDH_KEX_INIT_REPLY:
		return true;

	default:
		break;
	}

	return false;
}

inline void
Connection::HandlePacket(SSH::MessageNumber msg,
			 std::span<const std::byte> payload)
{
	if (!IsEncrypted())
		return CConnection::HandlePacket(msg, payload);

	if (IsOccupied() && !IsAllowedWhileOccupied(msg))
		throw Disconnect{
			SSH::DisconnectReasonCode::PROTOCOL_ERROR,
			"Occupied"sv
		};

	switch (msg) {
	case SSH::MessageNumber::SERVICE_REQUEST:
		HandleServiceRequest(payload);
		break;

	case SSH::MessageNumber::USERAUTH_REQUEST:
		HandleUserauthRequest(payload);
		break;

	default:
		SSH::CConnection::HandlePacket(msg, payload);
	}
}

void
Connection::OnBufferedError(std::exception_ptr e) noexcept
{
	logger(1, e);
	SSH::CConnection::OnBufferedError(std::move(e));
}
