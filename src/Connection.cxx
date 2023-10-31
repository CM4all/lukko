// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Connection.hxx"
#include "Instance.hxx"
#include "Listener.hxx"
#include "SessionChannel.hxx"
#include "SocketChannel.hxx"
#include "RConnect.hxx"
#include "key/Parser.hxx"
#include "key/Key.hxx"
#include "key/TextFile.hxx"
#include "ssh/Protocol.hxx"
#include "ssh/MakePacket.hxx"
#include "ssh/Deserializer.hxx"
#include "ssh/Channel.hxx"
#include "event/net/ConnectSocket.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "io/Beneath.hxx"
#include "io/FileAt.hxx"
#include "io/UniqueFileDescriptor.hxx"
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
		       UniqueSocketDescriptor _fd,
		       const SecretKeyList &_host_keys)
	:SSH::CConnection(_instance.GetEventLoop(), std::move(_fd),
			  _host_keys),
	 instance(_instance), listener(_listener),
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

	// TODO
	return getenv("HOME");
}

UniqueFileDescriptor
Connection::OpenHome() const noexcept
{
	UniqueFileDescriptor fd;

	if (const char *home = GetHome())
		fd.Open(home, O_PATH|O_DIRECTORY);

	return fd;
}

inline bool
Connection::IsAcceptedPublicKey(std::span<const std::byte> public_key_blob) noexcept
{
#ifdef ENABLE_TRANSLATION
	if (translation && translation->response.authorized_keys != nullptr &&
	    PublicKeysTextFileContains(translation->response.authorized_keys,
				       public_key_blob))
		return true;
#endif // ENABLE_TRANSLATION

	if (instance.GetGlobalAuthorizedKeys().Contains(public_key_blob))
		return true;

	if (auto home = OpenHome(); home.IsDefined()) {
		if (auto fd = TryOpenReadOnlyBeneath({home, ".ssh/authorized_keys"});
		    fd.IsDefined())
			if (PublicKeysTextFileContains(fd, public_key_blob))
				return true;
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

class ResolveSocketChannelOperation final : ConnectSocketHandler, Cancellable {
	Connection &connection;
	const SSH::ChannelInit init;
	CancellablePointer cancel_ptr;

public:
	ResolveSocketChannelOperation(Connection &_connection,
				      SSH::ChannelInit _init) noexcept
		:connection(_connection), init(_init) {}

	void Start(std::string_view host, unsigned port,
		   CancellablePointer &caller_cancel_ptr) noexcept {
		caller_cancel_ptr = *this;
		ResolveConnectTCP(connection, host, port, *this, cancel_ptr);
	}

private:
	// virtual methods from class ConnectSocketHandler
	void OnSocketConnectSuccess(UniqueSocketDescriptor fd) noexcept override {
		auto &_connection = connection;
		auto *channel = new SocketChannel(_connection, init, std::move(fd));
		delete this;
		_connection.AsyncChannelOpenSuccess(*channel);
	}

	void OnSocketConnectError(std::exception_ptr error) noexcept override {
		// TODO log error?
		connection.AsyncChannelOpenFailure(init,
						   SSH::ChannelOpenFailureReasonCode::CONNECT_FAILED,
						   GetFullMessage(error));
		delete this;
	}

	// virtual methods from class Cancellable
	virtual void Cancel() noexcept override {
		cancel_ptr.Cancel();
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

inline void
Connection::HandleUserauthRequest(std::span<const std::byte> payload)
{
	if (IsAuthenticated())
		/* RFC 4252 section 5.1: "When
		   SSH_MSG_USERAUTH_SUCCESS has been sent, any further
		   authentication requests received after that SHOULD
		   be silently ignored" */
		return;

	SSH::Deserializer d{payload};
	const auto to_be_signed_marker = d.Mark();
	const auto new_username = d.ReadString();
	const auto service_name = d.ReadString();
	const auto method_name = d.ReadString();

	fmt::print(stderr, "Userauth '{}' service='{}' method='{}'\n",
		   new_username, service_name, method_name);

	if (service_name != "ssh-connection"sv) {
		SendPacket(SSH::MakeUserauthFailure({}, false));
		return;
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
			if (change_password) {
				/* password change not implemented */
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				return;
			}

			password = d.ReadString();
			if (password.empty()) {
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				return;
			}
		}

		Allocator alloc;
		auto response = TranslateLogin(alloc, translation_server,
					       "ssh"sv, listener.GetTag(),
					       new_username, password);

		if (response.status != HttpStatus{}) {
			SendPacket(SSH::MakeUserauthFailure({}, false));
			return;
		}

		translation = std::make_unique<Translation>(std::move(alloc),
							    std::move(response));
		password_accepted = !password.empty();
	}
#endif // ENABLE_TRANSLATION

	if (method_name == "publickey"sv) {
		const bool with_signature = d.ReadBool();
		const auto public_key_algorithm = d.ReadString();
		const auto public_key_blob = d.ReadLengthEncoded();
		fmt::print(stderr, "  public_key_algorithm='{}'\n",
			   public_key_algorithm);

		if (!IsAcceptedPublicKey(public_key_blob)) {
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			return;
		}

		std::unique_ptr<PublicKey> public_key;

		try {
			public_key = ParsePublicKeyBlob(public_key_blob);
		} catch (...) {
			logger(1, "Failed to parse the client's public key: ",
			       std::current_exception());
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			return;
		}

		if (!with_signature) {
			SendPacket(SSH::MakeUserauthPkOk(public_key_algorithm,
							 public_key_blob));
			return;
		} else {
			const auto to_be_signed = d.Since(to_be_signed_marker);
			const auto signature = d.ReadLengthEncoded();

			try {
				SSH::Serializer s;
				s.WriteLengthEncoded(GetSessionId());
				s.WriteU8(static_cast<uint_least8_t>(SSH::MessageNumber::USERAUTH_REQUEST));
				s.WriteN(to_be_signed);

				if (!public_key->Verify(s.Finish(), signature)) {
					SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
					return;
				}
			} catch (...) {
				logger(1, "Failed to verify the client's public key: ",
				       std::current_exception());
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				return;
			}
		}
	} else if (method_name == "hostbased"sv) {
		// TODO only allow if explicitly enabled

		const auto public_key_algorithm = d.ReadString();
		const auto public_key_blob = d.ReadLengthEncoded();
		const auto client_host_name = d.ReadString();
		const auto client_user_name = d.ReadString();
		const auto to_be_signed = d.Since(to_be_signed_marker);
		const auto signature = d.ReadLengthEncoded();

		fmt::print(stderr, "  hostbased public_key_algorithm='{}' client_host_name='{}' client_user_name='{}'\n",
			   public_key_algorithm, client_host_name, client_user_name);

		if (!IsAcceptedHostPublicKey(public_key_blob)) {
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			return;
		}

		std::unique_ptr<PublicKey> public_key;

		try {
			public_key = ParsePublicKeyBlob(public_key_blob);
		} catch (...) {
			logger(1, "Failed to parse the client's host public key: ",
			       std::current_exception());
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			return;
		}

		try {
			SSH::Serializer s;
			s.WriteLengthEncoded(GetSessionId());
			s.WriteU8(static_cast<uint_least8_t>(SSH::MessageNumber::USERAUTH_REQUEST));
			s.WriteN(to_be_signed);

			if (!public_key->Verify(s.Finish(), signature)) {
				SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
				return;
			}
		} catch (...) {
			logger(1, "Failed to verify the client's public key: ",
			       std::current_exception());
			SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
			return;
		}
#ifdef ENABLE_TRANSLATION
	} else if (password_accepted) {
		/* the password was successfully verified by the
		   translation server */
#endif // ENABLE_TRANSLATION
	} else {
		SendPacket(SSH::MakeUserauthFailure(auth_methods, false));
		return;
	}

	username.assign(new_username);

	SetAuthenticated();
	SendPacket(SSH::PacketSerializer{SSH::MessageNumber::USERAUTH_SUCCESS});
}

inline void
Connection::HandlePacket(SSH::MessageNumber msg,
			 std::span<const std::byte> payload)
{
	if (!IsEncrypted())
		return CConnection::HandlePacket(msg, payload);

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
