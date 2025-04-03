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
#include "Delegate.hxx"
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
#include "lib/fmt/ToBuffer.hxx"
#include "spawn/Prepared.hxx"
#include "event/co/Sleep.hxx"
#include "event/net/CoConnectSocket.hxx"
#include "net/SocketError.hxx"
#include "net/StaticSocketAddress.hxx"
#include "net/ToString.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "io/Beneath.hxx"
#include "io/FileAt.hxx"
#include "io/UniqueFileDescriptor.hxx"
#include "co/InvokeTask.hxx"
#include "co/MultiAwaitable.hxx"
#include "co/Task.hxx"
#include "time/Cast.hxx"
#include "util/AllocatedArray.hxx"
#include "util/Cancellable.hxx"
#include "util/CharUtil.hxx"
#include "util/DeleteDisposer.hxx"
#include "util/Exception.hxx" // for GetFullMessage()
#include "util/IterableSplitString.hxx"
#include "util/StringAPI.hxx"
#include "util/StringCompare.hxx"
#include "util/StringVerify.hxx"

#ifdef ENABLE_TRANSLATION
#include "translation/LoginGlue.hxx"
#include "translation/Response.hxx"
#include "co/MultiLoader.hxx"
#include "AllocatorPtr.hxx"
#endif // ENABLE_TRANSLATION

#ifdef ENABLE_POND
#include "net/log/Datagram.hxx"
#include "net/log/Send.hxx"
#endif

#include <fmt/core.h>

#include <fcntl.h> // for O_*
#include <pwd.h>
#include <sys/stat.h>

using std::string_view_literals::operator""sv;

#ifdef ENABLE_TRANSLATION

struct Connection::Translation {
	/**
	 * A copy of the username.  We need this copy if
	 * TranslateService() if called during the authentication
	 * phase (e.g. by OpenInHome() / DelegateOpen()), when
	 * #username is not yet set.
	 */
	const std::string user;

	Allocator alloc;
	TranslateResponse response;

	/**
	 * The translation response for "SERVICE=sftp".  It is loaded
	 * on demand.
	 */
	Co::MultiLoader<TranslateResponse> sftp_response;

	/**
	 * The translation response for "SERVICE=rsync".  It is loaded
	 * on demand.
	 */
	Co::MultiLoader<TranslateResponse> rsync_response;

	Translation(std::string_view _user,
		    Allocator &&_alloc,
		    TranslateResponse &&_response) noexcept
		:user(_user),
		 alloc(std::move(_alloc)),
		 response(std::move(_response)) {}
};

static void
CheckChildOptions(const ChildOptions &options)
{
	if (options.uid_gid.effective_uid == UidGid::UNSET_UID)
		throw std::invalid_argument{"Translation response contains no UID"};

	if (options.uid_gid.effective_gid == UidGid::UNSET_GID)
		throw std::invalid_argument{"Translation response contains no GID"};

	if (!options.HasHome())
		throw std::invalid_argument{"Translation response contains no HOME"};
}

static void
CheckTranslateResponse(const TranslateResponse &response)
{
	// status must have been checked already
	assert(response.status == HttpStatus{});

	CheckChildOptions(response.child_options);
}

#endif // ENABLE_TRANSLATION

Connection::Connection(Instance &_instance, Listener &_listener,
		       PerClientAccounting *per_client,
		       UniqueSocketDescriptor _fd, SocketAddress _peer_address)
	:SSH::CConnection(_instance.GetEventLoop(), std::move(_fd),
			  SSH::Role::SERVER),
	 instance(_instance), listener(_listener),
	 peer_address(_peer_address),
	 local_address(GetSocket().GetLocalAddress()),
#ifdef ENABLE_POND
	 peer_host(listener.GetPondSocket().IsDefined() ? HostToString(peer_address) : std::string{}),
#endif
	 logger(StringLoggerDomain{ToString(peer_address)}),
	 auth_timeout(_instance.GetEventLoop(), BIND_THIS_METHOD(OnAuthTimeout))
{
	SetMetrics(instance.ssh_metrics);

	auth_timeout.Schedule(std::chrono::seconds{10});

	if (per_client != nullptr)
		per_client->AddConnection(accounting);
}

Connection::~Connection() noexcept
{
	socket_forward_listeners.clear_and_dispose(DeleteDisposer{});

	if (log_disconnect)
		LogFmt("Disconnected");
}

void
Connection::Terminate() noexcept
{
	if (log_disconnect) {
		log_disconnect = false;
		LogFmt("Terminating connection");
	}

	++instance.counters.n_terminated_connections;

	DoDisconnect(SSH::DisconnectReasonCode::CONNECTION_LOST,
		     "Account disabled"sv);
}

void
Connection::LogVFmt(fmt::string_view format_str, fmt::format_args args) noexcept
{
	constexpr unsigned level = 1;
	bool enabled = CheckLogLevel(level);

#ifdef ENABLE_POND
	const auto pond_socket = listener.GetPondSocket();
	if (pond_socket.IsDefined())
		enabled = true;
#endif

	if (!enabled)
		return;

	const auto message_buffer = VFmtBuffer<2048>(format_str, args);
	const std::string_view message{message_buffer};
	logger(1, message);

#ifdef ENABLE_POND
	if (!pond_socket.IsDefined())
		return;

	Net::Log::Datagram log_datagram{
		.timestamp = Net::Log::FromSystem(GetEventLoop().SystemNow()),
		.remote_host = peer_host.c_str(),
		.message = message,
		.type = Net::Log::Type::SSH,
	};

#ifdef ENABLE_TRANSLATION
	if (translation)
		log_datagram.site = translation->response.site;
#endif

	try {
		Net::Log::Send(pond_socket, log_datagram);
	} catch (...) {
		logger(1, std::current_exception());
	}
#endif // ENABLE_POND
}

SpawnService &
Connection::GetSpawnService() const noexcept
{
	return instance.GetSpawnService();
}

#ifdef ENABLE_TRANSLATION

inline Co::Task<const TranslateResponse &>
Connection::LazyTranslate(const char *translation_server,
			  std::string_view new_username,
			  std::string_view password) noexcept
{
	if (translation && password.empty() &&
	    new_username == translation->user)
		co_return translation->response;

	Allocator alloc;
	TranslateResponse response;

	try {
		response = co_await
			TranslateLogin(GetEventLoop(), alloc, translation_server,
				       "ssh"sv, listener.GetTag(),
				       new_username, password);
	} catch (...) {
		++instance.counters.n_translation_errors;
		logger(1, "Translation server error: ", std::current_exception());
		accounting.UpdateTokenBucket(2);
		throw Disconnect{
			SSH::DisconnectReasonCode::SERVICE_NOT_AVAILABLE,
			"Configuration server failed"sv,
		};
	}

	translation = std::make_unique<Translation>(new_username,
						    std::move(alloc),
						    std::move(response));
	co_return translation->response;
}

inline Co::Task<TranslateResponse>
Connection::TranslateService(std::string_view service) const noexcept
{
	assert(translation);
	assert(!translation->user.empty());

	const char *const translation_server = instance.GetTranslationServer();
	assert(translation_server != nullptr);

	auto response = co_await TranslateLogin(GetEventLoop(), translation->alloc,
						translation_server,
						service, listener.GetTag(),
						translation->user, {});

	if (response.status != HttpStatus{})
		throw std::runtime_error{"Translation server rejected LOGIN"};

	CheckTranslateResponse(response);

	co_return std::move(response);
}

const TranslateResponse *
Connection::GetTranslationResponse() const noexcept
{
	return translation
		? &translation->response
		: nullptr;
}

Co::Task<const TranslateResponse &>
Connection::GetTranslationResponse(SSH::Service service) const
{
	assert(translation);

	switch (service) {
	case SSH::Service::SSH:
		co_return translation->response;

	case SSH::Service::SFTP:
		co_return co_await translation->sftp_response.get([this]{ return TranslateService("sftp"sv); });

	case SSH::Service::RSYNC:
		co_return co_await translation->rsync_response.get([this]{ return TranslateService("rsync"sv); });
	}

	std::unreachable();
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
Connection::IsForwardingAllowed() const noexcept
{
	if (authorized_key_options.no_port_forwarding)
		return false;

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
		return translation->response.child_options.GetHome();
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

Co::Task<void>
Connection::PrepareChildProcess(PreparedChildProcess &p,
				[[maybe_unused]] FdHolder &close_fds,
				[[maybe_unused]] SSH::Service service) const noexcept
{
#ifdef ENABLE_TRANSLATION
	if (translation) {
		const auto &response = co_await GetTranslationResponse(service);
		response.child_options.CopyTo(p, close_fds);
		p.exec_path = response.execute;

		if (p.cgroup != nullptr && p.cgroup->IsDefined() &&
		    p.cgroup_session == nullptr) {
			/* create a session cgroup for each SSH
			   session */
			static unsigned session_id_counter = 0;
			p.strings.emplace_front(fmt::format("session-{}", ++session_id_counter));
			p.cgroup_session = p.strings.front().c_str();
		}
	} else {
#endif // ENABLE_TRANSLATION
		p.uid_gid.effective_uid = uid;
		p.uid_gid.effective_gid = gid;

		if (!home_path.empty())
			p.ns.mount.home = home_path.c_str();
#ifdef ENABLE_TRANSLATION
	}
#endif // ENABLE_TRANSLATION

	co_return;
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
			if (struct stat st;
			    fstat(fd.Get(), &st) == 0 &&
			    S_ISREG(st.st_mode) && st.st_size < 1024 * 1024) {
				if (auto options = PublicKeysTextFileContains(fd, public_key_blob)) {
					authorized_key_options = std::move(*options);
					co_return true;
				}
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

class LocalConnectSocketChannelOperation final : Cancellable {
	Connection &connection;
	const SSH::ChannelInit init;
	Co::InvokeTask invoke_task;
	UniqueSocketDescriptor socket;

public:
	LocalConnectSocketChannelOperation(Connection &_connection,
					   SSH::ChannelInit _init) noexcept
		:connection(_connection), init(_init) {}

	void Start(std::string_view path, CancellablePointer &caller_cancel_ptr) noexcept {
		caller_cancel_ptr = *this;
		invoke_task = Start(path);
		invoke_task.Start(BIND_THIS_METHOD(OnCompletion));
	}

private:
	Co::InvokeTask Start(std::string_view path) {
		auto fd = co_await DelegateLocalConnect(connection, path);
		socket = UniqueSocketDescriptor{std::move(fd)};
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
	virtual void Cancel() noexcept override { // Cancellable
		delete this;
	}
};

std::unique_ptr<SSH::Channel>
Connection::CreateChannel(std::string_view channel_type,
			  SSH::ChannelInit init,
			  std::span<const std::byte> payload,
			  CancellablePointer &cancel_ptr)
{
	logger.Fmt(1, "ChannelOpen type={:?} local_channel={} peer_channel={}"sv,
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
	} else if (channel_type == "direct-streamlocal@openssh.com") {
		SSH::Deserializer d{payload};
		const auto socket_path = d.ReadString();
		// Ignore remaining "reserved" fields (string, u32):
		// https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL#rev1.30

		// We have to impersonate the user to have access to their container's file system,
		// which contains the socket.
		auto *operation = new LocalConnectSocketChannelOperation(*this, init);
		operation->Start(socket_path, cancel_ptr);
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
	} else {
		++instance.counters.n_unsupported_service;
		throw Disconnect{SSH::DisconnectReasonCode::SERVICE_NOT_AVAILABLE,
			"Unsupported service"sv};
	}
}

static bool
IsValidUsername(std::string_view username) noexcept
{
	return username.size() <= 255 && CheckCharsNonEmpty(username, [](char ch){
		return IsAlphaNumericASCII(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '@';
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

	++instance.counters.n_userauth_received;

	logger.Fmt(1, "Userauth {:?} service={:?} method={:?}"sv,
		   new_username, service_name, method_name);

	if (const auto delay = accounting.GetDelay(); delay.count() > 0) {
		++instance.counters.n_tarpit;
		logger.Fmt(1, "Userauth tarpit {}s", ToFloatSeconds(delay));
		co_await Co::Sleep{GetEventLoop(), delay};
	}

	if (service_name != "ssh-connection"sv) {
		SendPacket(SSH::MakeUserauthFailure({}, false));
		co_return;
	}

	if (!IsValidUsername(new_username)) {
		accounting.UpdateTokenBucket(10);
		throw Disconnect{
			SSH::DisconnectReasonCode::ILLEGAL_USER_NAME,
			"Illegal user name"sv,
		};
	}

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
				++instance.counters.n_userauth_unsupported;
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				co_return;
			}

			if (password.empty()) {
				accounting.UpdateTokenBucket(10);
				++instance.counters.n_userauth_password_failed;
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				co_return;
			}

			accounting.UpdateTokenBucket(1);
		}

		const TranslateResponse &response = co_await LazyTranslate(translation_server,
									   new_username, password);

		if (response.status != HttpStatus{}) {
			accounting.UpdateTokenBucket(8);

			if (password.empty())
				++instance.counters.n_userauth_unknown_failed;
			else
				++instance.counters.n_userauth_password_failed;

			if (password.empty())
				LogFmt("Rejected auth for user {:?}{}{}"sv,
				       new_username,
				       response.message != nullptr ? ": "sv : ""sv,
				       response.message != nullptr ? response.message : "");
			else
				LogFmt("Failed password for user {:?}{}{}"sv,
				       new_username,
				       response.message != nullptr ? ": "sv : ""sv,
				       response.message != nullptr ? response.message : "");

			co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure({}, false));
			co_return;
		}

		if (response.token != nullptr &&
		    StringIsEqual(response.token, "sftp-only"))
			sftp_only = true;

		if (!password.empty())
			password_accepted = true;
		else if (response.no_password != nullptr) {
			password_accepted = true;

			if (StringIsEqual(response.no_password, "sftp"))
				sftp_only = true;
			else if (!StringIsEmpty(response.no_password))
				/* unrecognized NO_PASSWORD payload;
                                   we can't accept the password that
                                   way */
				password_accepted = false;
		}

		try {
			CheckTranslateResponse(response);
		} catch (...) {
			++instance.counters.n_translation_errors;
			logger(1, "Translation server error: ", std::current_exception());
			accounting.UpdateTokenBucket(2);
			throw Disconnect{
				SSH::DisconnectReasonCode::SERVICE_NOT_AVAILABLE,
				"Configuration server failed"sv,
			};
		}

		if (password_accepted)
			++instance.counters.n_userauth_password_accepted;
	} else
#endif // ENABLE_TRANSLATION
	{
		const auto *pw = getpwnam(std::string{new_username}.c_str());
		if (pw == nullptr) {
			++instance.counters.n_userauth_unknown_failed;
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

		logger.Fmt(1, "  public_key_algorithm={:?}"sv,
			   public_key_algorithm);

		accounting.UpdateTokenBucket(0.2);

		if (!co_await IsAcceptedPublicKey(public_key_blob)) {
			++instance.counters.n_userauth_publickey_failed;
			co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			co_return;
		}

		std::unique_ptr<PublicKey> public_key;

		try {
			public_key = ParsePublicKeyBlob(public_key_blob);
		} catch (...) {
			++instance.counters.n_userauth_publickey_failed;
			++instance.counters.n_protocol_errors;
			LogFmt("Failed to parse the client's public key: {}",
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
					++instance.counters.n_userauth_publickey_failed;
					co_await fail_sleep;
					SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
					co_return;
				}
			} catch (...) {
				++instance.counters.n_userauth_publickey_failed;
				LogFmt("Failed to verify the client's public key: {}",
				       std::current_exception());
				// TODO co_await fail_sleep;
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				co_return;
			}
		}

		++instance.counters.n_userauth_publickey_accepted;

		LogFmt("Accepted publickey for {:?}: {} {}"sv,
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

		logger.Fmt(1, "  hostbased public_key_algorithm={:?} client_host_name={:?} client_user_name={:?}"sv,
			   public_key_algorithm, client_host_name, client_user_name);

		if (!IsAcceptedHostPublicKey(public_key_blob)) {
			accounting.UpdateTokenBucket(10);
			++instance.counters.n_userauth_hostbased_failed;
			co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			co_return;
		}

		std::unique_ptr<PublicKey> public_key;

		try {
			public_key = ParsePublicKeyBlob(public_key_blob);
		} catch (...) {
			++instance.counters.n_userauth_hostbased_failed;
			++instance.counters.n_protocol_errors;
			LogFmt("Failed to parse the client's host public key: {}",
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
				++instance.counters.n_userauth_hostbased_failed;
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				co_return;
			}
		} catch (...) {
			++instance.counters.n_userauth_hostbased_failed;
			LogFmt("Failed to verify the client's public key: {}",
			       std::current_exception());
			// TODO co_await fail_sleep;
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			co_return;
		}

		++instance.counters.n_userauth_hostbased_accepted;
		LogFmt("Accepted hostkey for {:?}: {} {}"sv,
		       new_username,
		       public_key->GetType(), GetFingerprint(*public_key));
#ifdef ENABLE_TRANSLATION
	} else if (password_accepted) {
		/* the password was successfully verified by the
		   translation server */
		LogFmt("Accepted password for {:?}"sv,
		       new_username);
#endif // ENABLE_TRANSLATION
	} else {
		const bool is_none = method_name == "none"sv;
		if (!is_none)
			++instance.counters.n_userauth_unsupported_failed;
		accounting.UpdateTokenBucket(is_none ? 0.1 : 5.0);
		co_await fail_sleep;
		SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
		co_return;
	}

	username.assign(new_username);

	logger = Logger{fmt::format("{} user={:?}", logger.GetDomain(), username)};

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

	if (!have_service_userauth) {
		throw Disconnect{
			SSH::DisconnectReasonCode::PROTOCOL_ERROR,
			"Service ssh-userauth not requested"sv
		};
	}

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
	logger.Fmt(1, "GlobalRequest name={:?}"sv, request_name);

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
Connection::OnDisconnecting(SSH::DisconnectReasonCode reason_code,
			    std::string_view msg) noexcept
{
	CConnection::OnDisconnecting(reason_code, msg);

	/* some manual shutdown just in case the Destroy() is
           postponed */
	auth_timeout.Cancel();
	socket_forward_listeners.clear_and_dispose(DeleteDisposer{});
	occupied_task = {};

	if (log_disconnect) {
		log_disconnect = false;
		LogFmt("Disconnecting: {}", msg);
	}

	using C = SSH::DisconnectReasonCode;
	switch (reason_code) {
	case C::PROTOCOL_ERROR:
	case C::KEY_EXCHANGE_FAILED:
	case C::MAC_ERROR:
	case C::COMPRESSION_ERROR:
	case C::ILLEGAL_USER_NAME:
	case C::PROTOCOL_VERSION_NOT_SUPPORTED:
		++instance.counters.n_protocol_errors;
		break;

	case C::TOO_MANY_CONNECTIONS:
	case C::HOST_NOT_ALLOWED_TO_CONNECT:
		++instance.counters.n_rejected_connections;
		break;

	case C::RESERVED:
	case C::SERVICE_NOT_AVAILABLE:
	case C::HOST_KEY_NOT_VERIFIABLE:
	case C::CONNECTION_LOST:
	case C::BY_APPLICATION:
	case C::AUTH_CANCELLED_BY_USER:
	case C::NO_MORE_AUTH_METHODS_AVAILABLE:
		break;
	}
}

void
Connection::OnDisconnected([[maybe_unused]] SSH::DisconnectReasonCode reason_code,
			   std::string_view msg) noexcept
{
	if (log_disconnect) {
		log_disconnect = false;
		LogFmt("Client disconnected: {}", msg);
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

	++instance.counters.n_userauth_timeouts;
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
