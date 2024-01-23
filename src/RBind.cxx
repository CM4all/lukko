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
#include "event/AwaitableSocketEvent.hxx"
#include "net/EasyMessage.hxx"
#include "net/RBindSocket.hxx"
#include "net/SendMessage.hxx"
#include "net/SocketProtocolError.hxx"
#include "io/Iovec.hxx"
#include "util/SpanCast.hxx"
#include "util/StringCompare.hxx"
#include "util/StringAPI.hxx"

static UniqueSocketDescriptor
SshResolveBindStreamSocket(const char *host, unsigned port)
{
	if (StringIsEqual(host, "localhost"))
		/* special case in RFC 4254 7.1; by binding to all
		   addresses on the loopback device, we can bind both
		   IPv4 and IPv6 with one socket */
		return BindLoopback(SOCK_STREAM, port);
	else if (StringIsEmpty(host))
		/* another special case in RFC 4254 7.1 */
		/* in the SSH protocol, this is an empty string */
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

	std::array v{
		MakeIovec(ReferenceAsWritableBytes(port)),
		MakeIovec(std::as_writable_bytes(std::span{host})),
	};

	auto nbytes = control.Receive(v);
	if (nbytes < 0)
		throw MakeSocketError("recvmsg() failed");

	if (static_cast<std::size_t>(nbytes) < sizeof(port))
		throw SocketClosedPrematurelyError{};

	std::size_t host_length = static_cast<std::size_t>(nbytes) - sizeof(port);
	if (host_length >= sizeof(host))
		throw SocketBufferFullError{};

	host[host_length] = 0;

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

static void
SendResolveBindRequest(SocketDescriptor socket,
			  std::string_view host, const unsigned &port)
{
	const std::array v{
		MakeIovec(ReferenceAsBytes(port)),
		MakeIovec(AsBytes(host)),
	};

	const auto nbytes = SendMessage(socket, MessageHeader{v},
					MSG_NOSIGNAL);
	if (nbytes != sizeof(port) + host.size())
		throw SocketBufferFullError{};
}

static Co::Task<UniqueSocketDescriptor>
SpawnResolveBind(EventLoop &event_loop, SocketDescriptor socket,
		    std::string_view host, const unsigned &port)
{
	SendResolveBindRequest(socket, host, port);

	co_await AwaitableSocketEvent(event_loop, socket, SocketEvent::READ);

	auto fd = EasyReceiveMessageWithOneFD(socket);
	if (!fd.IsDefined())
		throw SocketProtocolError{"Bad number of fds"};

	co_return UniqueSocketDescriptor{fd.Release()};
}

static Co::Task<UniqueSocketDescriptor>
NsResolveBindTCP(EventLoop &event_loop,
		 SpawnService &spawn_service, const ChildOptions &options,
		 std::string_view host, const unsigned port)
{
	auto [control_socket, child_handle] =
		SpawnNsResolveBindTCPFunction(spawn_service, options);

	co_return co_await SpawnResolveBind(event_loop, control_socket, host, port);
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
