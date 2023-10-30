// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "RConnect.hxx"
#include "net/RConnectSocket.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "config.h"

#include <string>

#ifdef ENABLE_TRANSLATION

#include "Connection.hxx"
#include "translation/Response.hxx"
#include "spawn/ChildOptions.hxx"
#include "spawn/ProcessHandle.hxx"
#include "spawn/Prepared.hxx"
#include "spawn/Interface.hxx"
#include "net/ReceiveMessage.hxx"
#include "net/ScmRightsBuilder.hxx"
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

	control.Receive(ReferenceAsWritableBytes(port));
	auto nbytes = control.Receive(std::as_writable_bytes(std::span{host}));
	if (nbytes < 0)
		throw MakeSocketError("Failed to receive");

	if (nbytes == 0)
		throw SocketClosedPrematurelyError{};

	if (static_cast<std::size_t>(nbytes) >= sizeof(host))
		throw SocketBufferFullError{};

	host[nbytes] = 0;

	auto socket = ResolveConnectStreamSocket(host, port,
						 std::chrono::seconds{5});

	static constexpr std::byte dummy[1]{};
	static constexpr struct iovec v[1] = {
		MakeIovec(dummy),
	};

	MessageHeader msg{v};
	ScmRightsBuilder<1> b{msg};
	b.push_back(socket.Get());
	b.Finish(msg);

	SendMessage(control, msg, 0);

	return 0;
}

static std::pair<UniqueSocketDescriptor, std::unique_ptr<ChildProcessHandle>>
SpawnNsResolveConnectTCPFunction(SpawnService &spawn_service,
				 const ChildOptions &options)
{
	// TODO this is a horrible and inefficient kludge
	UniqueSocketDescriptor control_socket, control_socket_for_child;
	if (!UniqueSocketDescriptor::CreateSocketPair(AF_LOCAL, SOCK_SEQPACKET, 0,
						      control_socket,
						      control_socket_for_child))
		throw MakeSocketError("Failed to create control socket");

	PreparedChildProcess p;
	p.exec_function = NsResolveConnectTCPFunction;
	p.args.push_back("dummy");
	p.ns = {ShallowCopy{}, options.ns};
	p.ns.enable_pid = false;
	p.ns.enable_cgroup = false;
	p.ns.enable_ipc = false;
	p.ns.pid_namespace = nullptr;
	p.uid_gid = options.uid_gid;
	p.forbid_multicast = options.forbid_multicast;
	p.forbid_bind = options.forbid_bind;
	p.SetControl(std::move(control_socket_for_child));

	return {
		std::move(control_socket),
		spawn_service.SpawnChildProcess("connect", std::move(p)),
	};
}

static UniqueSocketDescriptor
NsResolveConnectTCP(SpawnService &spawn_service, const ChildOptions &options,
		    std::string_view host, const unsigned port)
{
	auto [control_socket, child_handle] =
		SpawnNsResolveConnectTCPFunction(spawn_service, options);
	control_socket.Send(ReferenceAsBytes(port));
	control_socket.Send(AsBytes(host));

	ReceiveMessageBuffer<1, CMSG_SPACE(sizeof(int) * 1)> rbuf;
	auto r = ReceiveMessage(control_socket, rbuf, 0);
        if (r.fds.size() != 1)
		throw std::runtime_error{"Bad number of fds"};

	return UniqueSocketDescriptor{r.fds.front().Release()};
}

#endif // ENABLE_TRANSLATION

UniqueSocketDescriptor
ResolveConnectTCP([[maybe_unused]] const Connection &ssh_connection,
		  std::string_view host, unsigned port)
{
#ifdef ENABLE_TRANSLATION
	if (const auto *tr = ssh_connection.GetTranslationResponse()) {
		// TODO switch uid/gid?

		if (tr->child_options.ns.network_namespace != nullptr)
			return NsResolveConnectTCP(ssh_connection.GetSpawnService(),
						   tr->child_options,
						   host, port);
	}
#endif // ENABLE_TRANSLATION

	return ResolveConnectStreamSocket(std::string{host}.c_str(), port,
					  std::chrono::seconds{5});
}
