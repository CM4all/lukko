// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Connection.hxx"
#include "Instance.hxx"
#include "Listener.hxx"
#include "SessionChannel.hxx"
#include "SocketChannel.hxx"
#include "SocketForwardListener.hxx"
#include "RConnect.hxx"
#include "RBind.hxx"
#include "DelegateOpen.hxx"
#include "DebugMode.hxx"
#include "key/Parser.hxx"
#include "key/Key.hxx"
#include "key/TextFile.hxx"
#include "key/Fingerprint.hxx"
#include "ssh/Protocol.hxx"
#include "ssh/MakePacket.hxx"
#include "ssh/ParsePacket.hxx"
#include "ssh/Deserializer.hxx"
#include "ssh/Channel.hxx"
#include "lib/fmt/ExceptionFormatter.hxx"
#include "lib/fmt/SocketAddressFormatter.hxx"
#include "spawn/Prepared.hxx"
#include "event/net/CoConnectSocket.hxx"
#include "net/SocketError.hxx"
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
#include "util/DeleteDisposer.hxx"
#include "util/Exception.hxx" // for GetFullMessage()
#include "util/IterableSplitString.hxx"
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

	/**
	 * Because SessionChannel::OnRequest() is not a coroutine, we
	 * must always query the translation for "sftp" from within
	 * Connection::CoHandleUserauthRequest().  This is where we
	 * store it.
	 *
	 * TODO query #sftp_response only when needed.
	 */
	TranslateResponse sftp_response;

	Translation(Allocator &&_alloc,
		    TranslateResponse &&_response,
		    TranslateResponse &&_sftp_response) noexcept
		:alloc(std::move(_alloc)),
		 response(std::move(_response)),
		 sftp_response(std::move(_sftp_response)) {}
};

#endif // ENABLE_TRANSLATION

Connection::Connection(Instance &_instance, Listener &_listener,
		       UniqueSocketDescriptor _fd, SocketAddress _peer_address)
	:SSH::CConnection(_instance.GetEventLoop(), std::move(_fd),
			  SSH::Role::SERVER),
	 instance(_instance), listener(_listener),
	 peer_address(_peer_address),
	 local_address(GetSocket().GetLocalAddress()),
	 logger(StringLoggerDomain{fmt::format("{}", peer_address)}),
	 auth_timeout(_instance.GetEventLoop(), BIND_THIS_METHOD(OnAuthTimeout))
{
	auth_timeout.Schedule(std::chrono::seconds{10});
}

Connection::~Connection() noexcept
{
	socket_forward_listeners.clear_and_dispose(DeleteDisposer{});

	if (log_disconnect)
		logger(1, "Disconnected");
}

void
Connection::Terminate() noexcept
{
	if (log_disconnect) {
		log_disconnect = false;
		logger(1, "Terminating connection");
	}

	DoDisconnect(SSH::DisconnectReasonCode::CONNECTION_LOST,
		     "Account disabled"sv);
}

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

bool
Connection::HasTag(std::string_view tag) const noexcept
{
	if (translation == nullptr)
		return false;

	for (std::string_view i : IterableSplitString(translation->response.child_options.tag, '\0'))
		if (i == tag)
			return true;

	return false;
}

#endif // ENABLE_TRANSLATION

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
		(void)fd.Open(home, O_PATH|O_DIRECTORY);

	return fd;
}

Co::Task<UniqueFileDescriptor>
Connection::OpenInHome(const char *path) const noexcept
{
	if (auto home = OpenHome(); home.IsDefined()) {
		if (auto fd = TryOpenReadOnlyBeneath({home, path});
		    fd.IsDefined() || errno != EACCES)
			co_return fd;
	}

	/* the plain open failed with EACCES; try again while
	   impersonating the target user */

	try {
		co_return co_await DelegateOpen(*this, path);
	} catch (...) {
		// TODO log error?
	}

	co_return UniqueFileDescriptor{};
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
Connection::PrepareChildProcess(PreparedChildProcess &p,
				[[maybe_unused]] bool sftp) const noexcept
{
#ifdef ENABLE_TRANSLATION
	if (translation) {
		(sftp ? translation->sftp_response : translation->response)
			.child_options.CopyTo(p);

		if (p.cgroup != nullptr && p.cgroup->name != nullptr &&
		    p.cgroup_session == nullptr) {
			/* create a session cgroup for each SSH
			   session */
			static unsigned session_id_counter = 0;
			p.strings.emplace_front(fmt::format("session-{}", ++session_id_counter));
			p.cgroup_session = p.strings.front().c_str();
		}
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
Connection::ShouldLoadHomeAuthorizedKeys() const noexcept
{
#ifdef ENABLE_TRANSLATION
	if (translation && translation->response.no_home_authorized_keys)
		return false;
#endif // ENABLE_TRANSLATION

	return true;
}

inline Co::Task<bool>
Connection::IsAcceptedPublicKey(std::span<const std::byte> public_key_blob) noexcept
{
#ifdef ENABLE_TRANSLATION
	if (translation && translation->response.authorized_keys != nullptr) {
		if (auto options =
		    PublicKeysTextFileContains(translation->response.authorized_keys,
					       public_key_blob)) {
			authorized_key_options = std::move(*options);
			co_return true;
		}
	}
#endif // ENABLE_TRANSLATION

	if (const auto *options = instance.GetGlobalAuthorizedKeys().Find(public_key_blob)) {
		authorized_key_options = *options;
		co_return true;
	}

	if (ShouldLoadHomeAuthorizedKeys()) {
		if (auto fd = co_await OpenInHome(".ssh/authorized_keys"); fd.IsDefined()) {
			if (auto options = PublicKeysTextFileContains(fd, public_key_blob)) {
				authorized_key_options = std::move(*options);
				co_return true;
			}
		}
	}

	co_return false;
}

inline bool
Connection::IsAcceptedHostPublicKey(std::span<const std::byte> public_key_blob) noexcept
{
	if (const auto *options = instance.GetAuthorizedHostKeys().Find(public_key_blob)) {
		authorized_key_options = *options;
		return true;
	}

	return false;
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
Connection::CreateChannel(std::string_view channel_type,
			  SSH::ChannelInit init,
			  std::span<const std::byte> payload,
			  CancellablePointer &cancel_ptr)
{
	logger.Fmt(1, "ChannelOpen type={} local_channel={} peer_channel={}"sv,
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

		logger.Fmt(1, "  connect=[{}]:{} originator=[{}]:{}"sv,
			   connect_host, connect_port,
			   originator_ip, originator_port);

		auto *operation = new ResolveSocketChannelOperation(*this, init);
		operation->Start(connect_host, connect_port, cancel_ptr);
		return {};
	} else
		return SSH::CConnection::CreateChannel(channel_type, init, payload,
						       cancel_ptr);
}

inline void
Connection::HandleServiceRequest(std::span<const std::byte> payload)
{
	const auto p = SSH::ParseServiceRequest(payload);

	if (p.service_name == "ssh-userauth"sv) {
		have_service_userauth = true;
		SendPacket(SSH::MakeServiceAccept(p.service_name));
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

inline Co::EagerInvokeTask
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

	logger.Fmt(1, "Userauth '{}' service='{}' method='{}'"sv,
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
		TranslateResponse response, sftp_response;

		try {
			response = co_await
				TranslateLogin(GetEventLoop(), alloc, translation_server,
					       "ssh"sv, listener.GetTag(),
					       new_username, password);

			sftp_response = co_await
				TranslateLogin(GetEventLoop(), alloc, translation_server,
					       "sftp"sv, listener.GetTag(),
					       new_username, {});
		} catch (...) {
			logger(1, "Translation server error: ", std::current_exception());
			throw Disconnect{
				SSH::DisconnectReasonCode::SERVICE_NOT_AVAILABLE,
				"Configuration server failed"sv,
			};
		}

		if (response.status != HttpStatus{}) {
			if (password.empty())
				logger.Fmt(1, "Rejected auth for user {}{}{}"sv,
					   new_username,
					   response.message != nullptr ? ": "sv : ""sv,
					   response.message != nullptr ? response.message : "");
			else
				logger.Fmt(1, "Failed password for user {}{}{}"sv,
					   new_username,
					   response.message != nullptr ? ": "sv : ""sv,
					   response.message != nullptr ? response.message : "");

			co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure({}, false));
			co_return;
		}

		translation = std::make_unique<Translation>(std::move(alloc),
							    std::move(response),
							    std::move(sftp_response));
		password_accepted = !password.empty();

		if (translation->response.no_password != nullptr)
			// TODO check the "no_password" payload
			password_accepted = true;
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

		logger.Fmt(1, "  public_key_algorithm='{}'"sv,
			   public_key_algorithm);

		if (!co_await IsAcceptedPublicKey(public_key_blob)) {
			co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			co_return;
		}

		std::unique_ptr<PublicKey> public_key;

		try {
			public_key = ParsePublicKeyBlob(public_key_blob);
		} catch (...) {
			logger.Fmt(1, "Failed to parse the client's public key: {}",
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
				logger.Fmt(1, "Failed to verify the client's public key: {}",
					   std::current_exception());
				// TODO co_await fail_sleep;
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				co_return;
			}
		}

		logger.Fmt(1, "Accepted publickey for {}: {} {}"sv,
			   new_username,
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

		logger.Fmt(1, "  hostbased public_key_algorithm='{}' client_host_name='{}' client_user_name='{}'"sv,
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
			logger.Fmt(1, "Failed to parse the client's host public key: {}",
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
			logger.Fmt(1, "Failed to verify the client's public key: {}",
				   std::current_exception());
			// TODO co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			co_return;
		}

		logger.Fmt(1, "Accepted hostkey for {}: {} {}"sv,
			   new_username,
			   public_key->GetType(), GetFingerprint(*public_key));
#ifdef ENABLE_TRANSLATION
	} else if (password_accepted) {
		/* the password was successfully verified by the
		   translation server */
		logger.Fmt(1, "Accepted password for {}"sv,
			   new_username);
#endif // ENABLE_TRANSLATION
	} else {
		co_await fail_sleep;
		SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
		co_return;
	}

	username.assign(new_username);

	auth_timeout.Cancel();

	if (const auto proxy_to = listener.GetProxyTo(); !proxy_to.IsNull()) {
		auto s = co_await CoConnectSocket(GetEventLoop(), proxy_to, std::chrono::seconds{10});

		OutgoingConnectionHandler &handler = *this;
		outgoing = std::make_unique<OutgoingConnection>(GetEventLoop(), std::move(s), handler);
		outgoing_ready = false;
	} else {
		SetAuthenticated();
		SendPacket(SSH::PacketSerializer{SSH::MessageNumber::USERAUTH_SUCCESS});
	}
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
			CloseError(std::move(error));
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

	if (!have_service_userauth)
		throw Disconnect{
			SSH::DisconnectReasonCode::PROTOCOL_ERROR,
			"Service ssh-userauth not requested"sv
		};

	if (!got_userauth_request) {
		/* this is the first USERAUTH_REQUEST - reschedule the
		   timeout with a longer duration */
		got_userauth_request = true;
		auth_timeout.Schedule(std::chrono::minutes{2});
	}

	/* the payload is owned by the caller, therefore we need to
	   duplicate it into an AllocatedArray onwed by the coroutine,
	   so the coroutine can keep using it after this method
	   returns */
	occupied_task = CoHandleUserauthRequest(AllocatedArray{payload});

	/* we're using EagerInvokeTask here because early errors get
	   rethrown out of this method instead of being passed to
	   OnUserauthCompletion(); the latter would destroy this
	   Connection instance, but this method wouldn't know and
	   would continue accessing it */
	occupied_task.Start(BIND_THIS_METHOD(OnUserauthCompletion));
}

Co::EagerTask<bool>
Connection::HandleGlobalRequest(std::string_view request_name,
				std::span<const std::byte> request_specific_data)
{
	logger.Fmt(1, "GlobalRequest name={}"sv, request_name);

	if (request_name == "tcpip-forward"sv) {
		if (!IsBindingAllowed())
			co_return false;

		SSH::Deserializer d{request_specific_data};
		/* copy the string because the co_await will
		   invalidate the request_specific_data buffer */
		std::string bind_address{d.ReadString()};
		const auto bind_port = d.ReadU32();
		d.ExpectEnd();

		logger.Fmt(1, "  bind=[{}]:{}"sv, bind_address, bind_port);

		// TODO support special strings according to RFC 4254 7.1
		// TODO suport bind_port==0 (REQUEST_SUCCESS contains port number)

		auto s = co_await ResolveBindTCP(*this, bind_address, bind_port);
		if (!s.Listen(16))
			throw MakeSocketError("listen() failed");

		auto *l = new SocketForwardListener(*this, std::move(bind_address),
						    bind_port, std::move(s));
		socket_forward_listeners.push_back(*l);

		co_return true;
	} else if (request_name == "cancel-tcpip-forward"sv) {
		SSH::Deserializer d{request_specific_data};
		const auto bind_address = d.ReadString();
		const auto bind_port = d.ReadU32();
		d.ExpectEnd();

		co_return socket_forward_listeners.remove_and_dispose_if([bind_address, bind_port](const auto &l){
			return l.IsBindAddress(bind_address, bind_port);
		}, DeleteDisposer{}) > 0;
	} else
		co_return false;
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

void
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

	if (outgoing && outgoing_ready) {
		switch (msg) {
		case SSH::MessageNumber::GLOBAL_REQUEST:
		case SSH::MessageNumber::REQUEST_SUCCESS:
		case SSH::MessageNumber::REQUEST_FAILURE:
		case SSH::MessageNumber::CHANNEL_OPEN:
		case SSH::MessageNumber::CHANNEL_OPEN_CONFIRMATION:
		case SSH::MessageNumber::CHANNEL_OPEN_FAILURE:
		case SSH::MessageNumber::CHANNEL_WINDOW_ADJUST:
		case SSH::MessageNumber::CHANNEL_DATA:
		case SSH::MessageNumber::CHANNEL_EXTENDED_DATA:
		case SSH::MessageNumber::CHANNEL_EOF:
		case SSH::MessageNumber::CHANNEL_CLOSE:
		case SSH::MessageNumber::CHANNEL_REQUEST:
		case SSH::MessageNumber::CHANNEL_SUCCESS:
		case SSH::MessageNumber::CHANNEL_FAILURE:
			outgoing->SendPacket(msg, payload);
			return;

		default:
			break;
		}
	}

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

std::string_view
Connection::GetServerHostKeyAlgorithms() const noexcept
{
	return instance.GetHostKeys().GetAlgorithms();
}

std::pair<const SecretKey *, std::string_view>
Connection::ChooseHostKey(std::string_view algorithms) const noexcept
{
	return instance.GetHostKeys().Choose(algorithms);
}

void
Connection::OnDisconnecting([[maybe_unused]] SSH::DisconnectReasonCode reason_code,
			    std::string_view msg) noexcept
{
	if (log_disconnect) {
		log_disconnect = false;
		logger.Fmt(1, "Disconnecting: {}", msg);
	}
}

void
Connection::OnDisconnected([[maybe_unused]] SSH::DisconnectReasonCode reason_code,
			   std::string_view msg) noexcept
{
	if (log_disconnect) {
		log_disconnect = false;
		logger.Fmt(1, "Client disconnected: {}", msg);
	}
}

void
Connection::OnBufferedError(std::exception_ptr e) noexcept
{
	logger(1, e);
	SSH::CConnection::OnBufferedError(std::move(e));
}

void
Connection::OnAuthTimeout() noexcept
{
	if (log_disconnect) {
		log_disconnect = false;
		logger(1, "Authentication timeout");
	}

	DoDisconnect(SSH::DisconnectReasonCode::CONNECTION_LOST,
		     "Timeout"sv);
}

void
Connection::OnOutgoingDestroy() noexcept
{
	outgoing.reset();

	// TODO
	DoDisconnect(SSH::DisconnectReasonCode::CONNECTION_LOST,
		     "Disconnected"sv);
}

void
Connection::OnOutgoingUserauthService()
{
	assert(outgoing);
	assert(!outgoing_ready);

	const auto [key, algorithm] = instance.GetHostKeys().Choose("ssh-ed25519"sv); // TODO
	if (key == nullptr)
		throw std::runtime_error{"No host key"};

	outgoing->SendUserauthRequestHostbased(username, *key, algorithm);
}

void
Connection::OnOutgoingUserauthSuccess()
{
	assert(outgoing);
	assert(!outgoing_ready);

	outgoing_ready = true;

	SetAuthenticated();
	SendPacket(SSH::PacketSerializer{SSH::MessageNumber::USERAUTH_SUCCESS});
}

void
Connection::OnOutgoingUserauthFailure()
{
	assert(outgoing);
	assert(!outgoing_ready);

	// TODO
	DoDisconnect(SSH::DisconnectReasonCode::CONNECTION_LOST,
		     "Proxy auth failed"sv);
	throw Destroyed{};
}

void
Connection::OnOutgoingHandlePacket(SSH::MessageNumber msg,
				   std::span<const std::byte> payload)
{
	assert(outgoing);
	assert(outgoing_ready);

	SendPacket(msg, payload);
}

void
Connection::OnOutgoingDisconnecting([[maybe_unused]] SSH::DisconnectReasonCode reason_code,
				    std::string_view msg) noexcept
{
	if (log_disconnect) {
		log_disconnect = false;
		logger.Fmt(1, "Disconnecting outgoing: {}", msg);
	}
}

void
Connection::OnOutgoingDisconnected([[maybe_unused]] SSH::DisconnectReasonCode reason_code,
				   std::string_view msg) noexcept
{
	if (log_disconnect) {
		log_disconnect = false;
		logger.Fmt(1, "Outgoing server disconnected: {}", msg);
	}
}
