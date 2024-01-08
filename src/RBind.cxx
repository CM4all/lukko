// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "RBind.hxx"
#include "Connection.hxx"
#include "net/BindSocket.hxx"
#include "net/SocketAddress.hxx"
#include "net/SocketError.hxx"
#include "net/SocketPair.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "co/AwaitableHelper.hxx"
#include "co/Task.hxx"
#include "config.h"

#include <string>

using std::string_view_literals::operator""sv;

#ifdef HAVE_NLOHMANN_JSON
#include "event/systemd/CoResolvedClient.hxx"
#else
#include "net/AddressInfo.hxx"
#include "net/Resolver.hxx"
#endif

#ifdef ENABLE_TRANSLATION

#include "translation/Response.hxx"
#include "spawn/ChildOptions.hxx"
#include "spawn/ProcessHandle.hxx"
#include "spawn/Prepared.hxx"
#include "spawn/Interface.hxx"
#include "net/EasyMessage.hxx"
#include "net/RBindSocket.hxx"
#include "net/SocketProtocolError.hxx"
#include "io/Iovec.hxx"
#include "util/SpanCast.hxx"
#include "util/StringAPI.hxx"

static UniqueSocketDescriptor
SshResolveBindStreamSocket(const char *host, unsigned port)
{
	if (StringIsEqual(host, "localhost"))
		/* special case in RFC 4254 7.1; by binding to all
		   addresses on the loopback device, we can bind both
		   IPv4 and IPv6 with one socket */
		return BindLoopback(SOCK_STREAM, port);
	else if (StringIsEqual(host, "*"))
		/* another special case in RFC 4254 7.1 */
		/* in the SSH protocol, this is an empty string; the
		   "*" is just a placeholder because our internal
		   protocol can't handle empty strings */
		return BindPort(SOCK_STREAM, port);
	else
		return ResolveBindStreamSocket(host, port);
}

static int
NsResolveBindTCPFunction(PreparedChildProcess &&)
{
	SocketDescriptor control{3};
	unsigned port;
	char host[1024];

	control.Receive(ReferenceAsWritableBytes(port));
	auto nbytes = control.Receive(std::as_writable_bytes(std::span{host}));
	if (nbytes < 0)
		throw MakeSocketError("Failed to receive");

	if (nbytes == 0)
		throw SocketClosedPrematurelyError{};

	if (static_cast<std::size_t>(nbytes) >= sizeof(host))
		throw SocketBufferFullError{};

	host[nbytes] = 0;

	auto socket = SshResolveBindStreamSocket(host, port);
	EasySendMessage(control, socket.ToFileDescriptor());

	return 0;
}

static std::pair<UniqueSocketDescriptor, std::unique_ptr<ChildProcessHandle>>
SpawnNsResolveBindTCPFunction(SpawnService &spawn_service,
				 const ChildOptions &options)
{
	// TODO this is a horrible and inefficient kludge
	auto [control_socket, control_socket_for_child] = CreateSocketPair(SOCK_SEQPACKET);

	PreparedChildProcess p;
	p.exec_function = NsResolveBindTCPFunction;
	p.args.push_back("dummy");
	p.ns = {ShallowCopy{}, options.ns};
	p.ns.enable_pid = false;
	p.ns.enable_cgroup = false;
	p.ns.enable_ipc = false;
	p.ns.pid_namespace = nullptr;
	p.uid_gid = options.uid_gid;
#ifdef HAVE_LIBSECCOMP
	p.forbid_multicast = options.forbid_multicast;
	p.forbid_bind = options.forbid_bind;
#endif // HAVE_LIBSECCOMP
	p.SetControl(std::move(control_socket_for_child));

	return {
		std::move(control_socket),
		spawn_service.SpawnChildProcess("bind", std::move(p)),
	};
}

class SpawnResolveBindOperation final
{
	const std::unique_ptr<ChildProcessHandle> process;

	SocketEvent socket;

	std::coroutine_handle<> continuation;

	UniqueSocketDescriptor value;

	std::exception_ptr error;

	using Awaitable = Co::AwaitableHelper<SpawnResolveBindOperation>;
	friend Awaitable;

public:
	SpawnResolveBindOperation(EventLoop &event_loop,
				  UniqueSocketDescriptor _socket,
				  std::unique_ptr<ChildProcessHandle> &&_process,
				  std::string_view host, unsigned port)
		:process(std::move(_process)),
		 socket(event_loop, BIND_THIS_METHOD(OnSocketReady),
			_socket.Release())
		{
			if (host.empty())
				/* this protocol doesn't allow an
				   empty string, so use a
				   placeholder */
				host = "*"sv;

			auto s = socket.GetSocket();
			// TODO handle send errors
			s.Send(ReferenceAsBytes(port));
			s.Send(AsBytes(host));
			socket.ScheduleRead();
		}

	~SpawnResolveBindOperation() noexcept {
		socket.Close();
	}

	Awaitable operator co_await() noexcept {
		return *this;
	}

private:
	bool IsReady() const noexcept {
		return value.IsDefined() || error;
	}

	UniqueSocketDescriptor TakeValue() noexcept {
		return std::move(value);
	}

	void OnSocketReady([[maybe_unused]] unsigned events) noexcept {
		try {
			auto fd = EasyReceiveMessageWithOneFD(socket.GetSocket());
			if (!fd.IsDefined())
				throw std::runtime_error{"Bad number of fds"};

			value = UniqueSocketDescriptor{fd.Release()};
		} catch (...) {
			error = std::current_exception();
		}

		if (continuation)
			continuation.resume();
	}
};

static Co::Task<UniqueSocketDescriptor>
NsResolveBindTCP(EventLoop &event_loop,
		 SpawnService &spawn_service, const ChildOptions &options,
		 std::string_view host, const unsigned port)
{
	auto [control_socket, child_handle] =
		SpawnNsResolveBindTCPFunction(spawn_service, options);

	co_return co_await SpawnResolveBindOperation(event_loop, std::move(control_socket),
						     std::move(child_handle),
						     host, port);
}

#endif // ENABLE_TRANSLATION

static Co::Task<UniqueSocketDescriptor>
NormalResolveBindTCP([[maybe_unused]] EventLoop &event_loop,
		     std::string_view host, const unsigned port)
{
	if (host == "localhost"sv)
		/* special case in RFC 4254 7.1; by binding to all
		   addresses on the loopback device, we can bind both
		   IPv4 and IPv6 with one socket */
		co_return BindLoopback(SOCK_STREAM, port);
	else if (host.empty())
		/* another special case in RFC 4254 7.1 */
		co_return BindPort(SOCK_STREAM, port);

#ifdef HAVE_NLOHMANN_JSON
	// TODO use the other addresses as fallback?
	const auto addresses = co_await Systemd::CoResolveHostname(event_loop, host, port);
	const SocketAddress address = addresses.front();
#else
	/* no systemd support - using the (blocking) standard
	   resolver */
	static constexpr struct addrinfo hints = {
		.ai_flags = AI_ADDRCONFIG|AI_PASSIVE,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};

	const auto r = Resolve(std::string{host}.c_str(), port, &hints);
	const auto &address = r.GetBest();
#endif

	UniqueSocketDescriptor s;
	if (!s.CreateNonBlock(address.GetFamily(), SOCK_STREAM, 0))
		throw MakeSocketError("Failed to create socket");

	if (!s.Bind(address))
		throw MakeSocketError("Failed to bind");

	co_return std::move(s);
}

Co::Task<UniqueSocketDescriptor>
ResolveBindTCP(const Connection &ssh_connection,
	       std::string_view host, unsigned port) noexcept
{
#ifdef ENABLE_TRANSLATION
	if (const auto *tr = ssh_connection.GetTranslationResponse()) {
		// TODO switch uid/gid?

		if (tr->child_options.ns.network_namespace != nullptr)
			return NsResolveBindTCP(ssh_connection.GetEventLoop(),
						   ssh_connection.GetSpawnService(),
						   tr->child_options,
						   host, port);
	}
#endif // ENABLE_TRANSLATION

	return NormalResolveBindTCP(ssh_connection.GetEventLoop(), host, port);
}
