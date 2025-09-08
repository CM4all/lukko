// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "RConnect.hxx"
#include "Connection.hxx"
#include "event/net/CoConnectSocket.hxx"
#include "net/SocketAddress.hxx"
#include "net/SocketPair.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "co/Task.hxx"
#include "config.h"

#include <string>

#ifdef HAVE_NLOHMANN_JSON
#include "event/systemd/CoResolvedClient.hxx"
#else
#include "net/AddressInfo.hxx"
#include "net/Resolver.hxx"
#endif

#ifdef ENABLE_TRANSLATION

#include "translation/Response.hxx"
#include "translation/ExecuteOptions.hxx"
#include "spawn/CoEnqueue.hxx"
#include "spawn/CoWaitSpawnCompletion.hxx"
#include "spawn/ChildOptions.hxx"
#include "spawn/ProcessHandle.hxx"
#include "spawn/Prepared.hxx"
#include "spawn/Interface.hxx"
#include "event/AwaitableSocketEvent.hxx"
#include "net/EasyMessage.hxx"
#include "net/RConnectSocket.hxx"
#include "net/SendMessage.hxx"
#include "net/SocketError.hxx"
#include "net/SocketProtocolError.hxx"
#include "io/Iovec.hxx"
#include "util/SpanCast.hxx"

static int
NsResolveConnectTCPFunction(PreparedChildProcess &&)
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

	try {
		auto socket = ResolveConnectStreamSocket(host, port,
							       std::chrono::seconds{5});
		EasySendMessage(control, socket.ToFileDescriptor());
	} catch (...) {
		EasySendError(control, std::current_exception());
	}

	return 0;
}

static std::pair<UniqueSocketDescriptor, std::unique_ptr<ChildProcessHandle>>
SpawnNsResolveConnectTCPFunction(SpawnService &spawn_service,
				 const ChildOptions &options)
{
	// TODO this is a horrible and inefficient kludge
	auto [control_socket, control_socket_for_child] = CreateSocketPair(SOCK_SEQPACKET);

	PreparedChildProcess p;
	p.exec_function = NsResolveConnectTCPFunction;
	p.args.push_back("dummy");
	p.ns = {ShallowCopy{}, options.ns};
	p.ns.ClearPid();
	p.ns.ClearCgroup();
	p.ns.ClearIPC();
	p.uid_gid = options.uid_gid;
#ifdef HAVE_LIBSECCOMP
	p.forbid_multicast = options.forbid_multicast;
	p.forbid_bind = options.forbid_bind;
#endif // HAVE_LIBSECCOMP
	p.control_fd = control_socket_for_child.ToFileDescriptor();

	return {
		std::move(control_socket),
		spawn_service.SpawnChildProcess("connect", std::move(p)),
	};
}

static void
SendResolveConnectRequest(SocketDescriptor socket,
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
SpawnResolveConnect(EventLoop &event_loop, SocketDescriptor socket,
		    std::string_view host, const unsigned &port)
{
	SendResolveConnectRequest(socket, host, port);

	co_await AwaitableSocketEvent(event_loop, socket, SocketEvent::READ);

	auto fd = EasyReceiveMessageWithOneFD(socket);
	if (!fd.IsDefined())
		throw SocketProtocolError{"Bad number of fds"};

	co_return UniqueSocketDescriptor{std::move(fd)};
}

static Co::Task<UniqueSocketDescriptor>
NsResolveConnectTCP(EventLoop &event_loop,
		    SpawnService &spawn_service, const ChildOptions &options,
		    std::string_view host, const unsigned port)
{
	/* throttle if the spawner is under pressure */
	co_await CoEnqueueSpawner{spawn_service};

	auto [control_socket, child_handle] =
		SpawnNsResolveConnectTCPFunction(spawn_service, options);

	/* wait for spawner completion and rethrow errors */
	co_await CoWaitSpawnCompletion{*child_handle};

	co_return co_await SpawnResolveConnect(event_loop, control_socket, host, port);
}

#endif // ENABLE_TRANSLATION

static Co::Task<UniqueSocketDescriptor>
NormalResolveConnectTCP(EventLoop &event_loop,
			std::string_view host, const unsigned port)
{
#ifdef HAVE_NLOHMANN_JSON
	// TODO use the other addresses as fallback?
	const auto addresses = co_await Systemd::CoResolveHostname(event_loop, host, port);
	const SocketAddress address = addresses.front();
#else
	/* no systemd support - using the (blocking) standard
	   resolver */
	static constexpr struct addrinfo hints = {
		.ai_flags = AI_ADDRCONFIG,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};

	const auto r = Resolve(std::string{host}.c_str(), port, &hints);
	const auto &address = r.GetBest();
#endif

	co_return co_await CoConnectSocket(event_loop, address, std::chrono::seconds{5});
}

Co::Task<UniqueSocketDescriptor>
ResolveConnectTCP(const Connection &ssh_connection,
		  std::string_view host, unsigned port) noexcept
{
#ifdef ENABLE_TRANSLATION
	if (const auto *tr = ssh_connection.GetTranslationResponse()) {
		// TODO switch uid/gid?

		if (tr->execute_options != nullptr &&
		    tr->execute_options->child_options.ns.network_namespace != nullptr)
			return NsResolveConnectTCP(ssh_connection.GetEventLoop(),
						   ssh_connection.GetSpawnService(),
						   tr->execute_options->child_options,
						   host, port);
	}
#endif // ENABLE_TRANSLATION

	return NormalResolveConnectTCP(ssh_connection.GetEventLoop(), host, port);
}
