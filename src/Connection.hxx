// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "OutgoingConnection.hxx"
#include "Service.hxx"
#include "ssh/CConnection.hxx"
#include "key/Options.hxx"
#include "event/CoarseTimerEvent.hxx"
#include "net/AllocatedSocketAddress.hxx"
#include "net/ClientAccounting.hxx"
#include "io/Logger.hxx"
#include "co/InvokeTask.hxx"
#include "util/IntrusiveList.hxx"
#include "config.h"

#include <memory>

#include <sys/types.h> // for uid_t, gid_t

namespace Co { template<typename T> class Task; }
struct TranslateResponse;
struct ExecuteOptions;
struct PreparedChildProcess;
class FdHolder;
class Instance;
class Listener;
class PerClientAccounting;
class SocketForwardListener;
class UniqueFileDescriptor;
class SpawnService;
template<class T> class AllocatedArray;

namespace SSH {
class PacketSerializer;
}

class Connection final
	: public AutoUnlinkIntrusiveListHook,
	  public SSH::CConnection,
	  OutgoingConnectionHandler
{
	Instance &instance;
	Listener &listener;

	const AllocatedSocketAddress peer_address;
	const AllocatedSocketAddress local_address;

#ifdef ENABLE_POND
	const std::string peer_host;
#endif

	AccountedClientConnection accounting;

	Logger logger;

	/**
	 * This timer disconnects when the auth phase takes too long.
	 * At first, a very short duration is scheduled (10s) until
	 * encryption is established; when the first USERAUTH_REQUEST
	 * is received (#got_userauth), the timer is rescheduled,
	 * allowing some more time for the actual user auth.
	 */
	CoarseTimerEvent auth_timeout;

	AuthorizedKeyOptions authorized_key_options;

	std::string username;

#ifdef ENABLE_TRANSLATION
	struct Translation;
	std::unique_ptr<Translation> translation;
#endif // ENABLE_TRANSLATION

	uid_t uid;
	gid_t gid;
	std::string home_path;
	std::string shell;

	IntrusiveList<SocketForwardListener> socket_forward_listeners;

	/**
	 * If this is set, then the connection is currently occupied
	 * with an asynchronous operation (e.g. lookup in the user
	 * database).  Until it finishes, most incoming packets will
	 * cause the connection to be closed.
	 */
	Co::EagerInvokeTask occupied_task;

	std::unique_ptr<OutgoingConnection> outgoing;

#ifdef ENABLE_TRANSLATION
	bool sftp_only = false;
#else
	static constexpr bool sftp_only = false;
#endif

	bool log_disconnect = true;

	bool have_service_userauth = false;

	/**
	 * Tracks whether USERAUTH_REQUEST has been received already.
	 * This is used to reschedule #auth_timeout.
	 */
	bool got_userauth_request = false;

	bool outgoing_ready;

public:
	Connection(Instance &_instance, Listener &_listener,
		   PerClientAccounting *per_client,
		   UniqueSocketDescriptor fd, SocketAddress _peer_address);
	~Connection() noexcept;

	/**
	 * Terminate all processes and close the connection with code
	 * #CONNECTION_LOST.
	 */
	void Terminate() noexcept;

	const auto &GetLogger() const noexcept {
		return logger;
	}

	/**
	 * Log to both stderr (log level 1) and to Pond (if enabled).
	 */
	void LogVFmt(fmt::string_view format_str, fmt::format_args args) noexcept;

	template<typename S, typename... Args>
	void LogFmt(const S &format_str, Args&&... args) noexcept {
		LogVFmt(format_str, fmt::make_format_args(args...));
	}

	[[gnu::const]]
	SpawnService &GetSpawnService() const noexcept;

	Listener &GetListener() const noexcept {
		return listener;
	}

	const SocketAddress GetPeerAddress() const noexcept {
		return peer_address;
	}

	const SocketAddress GetLocalAddress() const noexcept {
		return local_address;
	}

	std::string_view GetUsername() const noexcept {
		return username;
	}

	const AuthorizedKeyOptions &GetAuthorizedKeyOptions() const noexcept {
		return authorized_key_options;
	}

	[[gnu::pure]]
	const char *GetShell() const noexcept;

#ifdef ENABLE_TRANSLATION
	bool HasTranslation() const noexcept {
		return (bool)translation;
	}

	/**
	 * Return the main translation response or nullptr if no
	 * translation server is configured.
	 */
	[[gnu::pure]]
	const TranslateResponse *GetTranslationResponse() const noexcept;

	/**
	 * Return the #ExecuteOptions for a specific service.
	 * Calling this method is only allowed if a translation server
	 * is used.  The method may suspend when the translation
	 * server gets queried.
	 *
	 * Throws on error.
	 */
	[[nodiscard]]
	Co::Task<const ExecuteOptions &> GetExecuteOptions(SSH::Service service) const;

	static void PrepareChildProcess(PreparedChildProcess &p,
					FdHolder &close_fds,
					const ExecuteOptions &options) noexcept;

	[[gnu::pure]]
	bool HasTag(std::string_view tag) const noexcept;
#endif

	[[gnu::pure]]
	bool IsSftpOnly() const noexcept {
		return sftp_only;
	}

	[[gnu::pure]]
	bool IsRsyncAllowed() const noexcept {
		return true;
	}

	[[gnu::pure]]
	bool IsExecAllowed() const noexcept {
		return !IsSftpOnly();
	}

	[[gnu::pure]]
	bool IsForwardingAllowed() const noexcept;

	[[gnu::pure]]
	bool IsBindingAllowed() const noexcept {
		return IsForwardingAllowed();
	}

	/**
	 * Do some preparations for spawning a child process for the
	 * currently user.
	 *
	 * @param sftp is this for an SFTP process with an empty
	 * rootfs?
	 */
	[[nodiscard]]
	Co::Task<void> PrepareChildProcess(PreparedChildProcess &p,
					   FdHolder &close_fds,
					   SSH::Service service) const noexcept;

	using SSH::Connection::DoDisconnect;

protected:
	void Destroy() noexcept override {
		delete this;
	}

private:
	bool IsOccupied() const noexcept {
		return occupied_task;
	}

	[[gnu::pure]]
	const char *GetHome() const noexcept;
	UniqueFileDescriptor OpenHome() const noexcept;

#ifdef ENABLE_TRANSLATION
	/**
	 * Perform the (primary) translation, but return the cached
	 * response if the username matches and the password is empty.
	 */
	Co::Task<const TranslateResponse &> LazyTranslate(const char *translation_server,
							  std::string_view new_username,
							  std::string_view password) noexcept;

	/**
	 * Perform a (secondary) translation with a different SERVICE,
	 * e.g. "sftp".
	 */
	Co::Task<ExecuteOptions> TranslateService(std::string_view service) const;
#endif

	/**
	 * Open a file in the home directory of the user (with
	 * O_RDONLY).
	 *
	 * @param path a path relative to the home directory
	 */
	Co::Task<UniqueFileDescriptor> OpenInHome(const char *path) const noexcept;

	[[gnu::pure]]
	bool ShouldLoadHomeAuthorizedKeys() const noexcept;

	/**
	 * This method modifies the `authorized_key_options` field if
	 * a matching key was found.
	 */
	Co::Task<bool> IsAcceptedPublicKey(std::span<const std::byte> public_key_blob) noexcept;

	/**
	 * This method modifies the `authorized_key_options` field if
	 * a matching key was found.
	 */
	bool IsAcceptedHostPublicKey(std::span<const std::byte> public_key_blob) noexcept;

	void HandleServiceRequest(std::span<const std::byte> payload);

	Co::EagerInvokeTask CoHandleUserauthRequest(AllocatedArray<std::byte> payload);
	void OnUserauthCompletion(std::exception_ptr error) noexcept;
	void HandleUserauthRequest(std::span<const std::byte> payload);

	void HandleChannelOpen(std::span<const std::byte> payload);

	void OnAuthTimeout() noexcept;

	/* virtual methods from class SSH::GConnection */
	Co::EagerTask<bool> HandleGlobalRequest(std::string_view request_name,
						std::span<const std::byte> request_specific_data) override;

	/* virtual methods from class SSH::CConnection */
	std::unique_ptr<SSH::Channel> CreateChannel(std::string_view channel_type,
						    SSH::ChannelInit init,
						    std::span<const std::byte> payload,
						    CancellablePointer &cancel_ptr) override;

	/* virtual methods from class SSH::Connection */
	void HandlePacket(SSH::MessageNumber msg,
			  std::span<const std::byte> payload) override;

	std::string_view GetServerHostKeyAlgorithms() const noexcept override;
	std::pair<const SecretKey *, std::string_view> ChooseHostKey(std::string_view algorithms) const noexcept override;
	void OnDisconnecting(SSH::DisconnectReasonCode reason_code,
			     std::string_view msg) noexcept override;
	void OnDisconnected(SSH::DisconnectReasonCode reason_code,
			    std::string_view msg) noexcept override;

	/* virtual methods from class BufferedSocketHandler */
	void OnBufferedError(std::exception_ptr e) noexcept override;

	/* virtual methods from class OutgoingConnectionHandler */
	void OnOutgoingDestroy() noexcept override;
	void OnOutgoingUserauthService() override;
	void OnOutgoingUserauthSuccess() override;
	[[noreturn]]
	void OnOutgoingUserauthFailure() override;
	void OnOutgoingHandlePacket(SSH::MessageNumber msg,
				    std::span<const std::byte> payload) override;
	void OnOutgoingDisconnecting(SSH::DisconnectReasonCode reason_code,
				     std::string_view msg) noexcept override;
	void OnOutgoingDisconnected(SSH::DisconnectReasonCode reason_code,
				    std::string_view msg) noexcept override;
};
