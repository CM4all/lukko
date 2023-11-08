// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

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
#include "spawn/ChildOptions.hxx"
#include "spawn/ProcessHandle.hxx"
#include "spawn/Prepared.hxx"
#include "spawn/Interface.hxx"
#include "net/RConnectSocket.hxx"
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
	auto [control_socket, control_socket_for_child] = CreateSocketPair(SOCK_SEQPACKET);

	PreparedChildProcess p;
	p.exec_function = NsResolveConnectTCPFunction;
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
		spawn_service.SpawnChildProcess("connect", std::move(p)),
	};
}

class SpawnResolveConnectOperation final
{
	const std::unique_ptr<ChildProcessHandle> process;

	SocketEvent socket;

	std::coroutine_handle<> continuation;

	UniqueSocketDescriptor value;

	std::exception_ptr error;

public:
	SpawnResolveConnectOperation(EventLoop &event_loop,
				     UniqueSocketDescriptor _socket,
				     std::unique_ptr<ChildProcessHandle> &&_process,
				     std::string_view host, unsigned port)
		:process(std::move(_process)),
		 socket(event_loop, BIND_THIS_METHOD(OnSocketReady),
			_socket.Release())
	{
		auto s = socket.GetSocket();
		// TODO handle send errors
		s.Send(ReferenceAsBytes(port));
		s.Send(AsBytes(host));
		socket.ScheduleRead();
	}

	~SpawnResolveConnectOperation() noexcept {
		socket.Close();
	}

	auto operator co_await() noexcept {
		struct Awaitable final {
			SpawnResolveConnectOperation &task;

			bool await_ready() const noexcept {
				return task.value.IsDefined() || task.error;
			}

			std::coroutine_handle<> await_suspend(std::coroutine_handle<> _continuation) noexcept {
				task.continuation = _continuation;
				return std::noop_coroutine();
			}

			decltype(auto) await_resume() {
				if (task.error)
					std::rethrow_exception(task.error);

				return std::move(task.value);
			}
		};

		return Awaitable{*this};
	}

private:
	void OnSocketReady([[maybe_unused]] unsigned events) noexcept {
		try {
			ReceiveMessageBuffer<1, CMSG_SPACE(sizeof(int) * 1)> rbuf;
			auto r = ReceiveMessage(socket.GetSocket(), rbuf, 0);
			if (r.fds.size() != 1)
				throw std::runtime_error{"Bad number of fds"};

			value = UniqueSocketDescriptor{r.fds.front().Release()};
			// TODO why does this not compile?
			//value = std::move(r.fds.front());
		} catch (...) {
			error = std::current_exception();
		}

		if (continuation)
			continuation.resume();
	}
};

static Co::Task<UniqueSocketDescriptor>
NsResolveConnectTCP(EventLoop &event_loop,
		    SpawnService &spawn_service, const ChildOptions &options,
		    std::string_view host, const unsigned port)
{
	auto [control_socket, child_handle] =
		SpawnNsResolveConnectTCPFunction(spawn_service, options);

	co_return co_await SpawnResolveConnectOperation(event_loop, std::move(control_socket),
							std::move(child_handle),
							host, port);
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

		if (tr->child_options.ns.network_namespace != nullptr)
			return NsResolveConnectTCP(ssh_connection.GetEventLoop(),
						   ssh_connection.GetSpawnService(),
						   tr->child_options,
						   host, port);
	}
#endif // ENABLE_TRANSLATION

	return NormalResolveConnectTCP(ssh_connection.GetEventLoop(), host, port);
}
