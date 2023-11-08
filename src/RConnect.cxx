// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "RConnect.hxx"
#include "Connection.hxx"
#include "event/net/ConnectSocket.hxx"
#include "net/SocketAddress.hxx"
#include "net/SocketPair.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "config.h"

#include <string>

#ifdef HAVE_NLOHMANN_JSON
#include "event/systemd/ResolvedClient.hxx"
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

class SpawnResolveConnectOperation final : Cancellable
{
	const std::unique_ptr<ChildProcessHandle> process;

	SocketEvent socket;

	ConnectSocketHandler &handler;

public:
	SpawnResolveConnectOperation(EventLoop &event_loop,
				     UniqueSocketDescriptor _socket,
				     std::unique_ptr<ChildProcessHandle> &&_process,
				     ConnectSocketHandler &_handler) noexcept
		:process(std::move(_process)),
		 socket(event_loop, BIND_THIS_METHOD(OnSocketReady),
			_socket.Release()),
		 handler(_handler) {}

	~SpawnResolveConnectOperation() noexcept {
		socket.Close();
	}

	auto &GetEventLoop() const noexcept {
		return socket.GetEventLoop();
	}

	void Start(std::string_view host, unsigned port,
		   CancellablePointer &cancel_ptr) noexcept {
		cancel_ptr = *this;

		auto s = socket.GetSocket();
		// TODO handle send errors
		s.Send(ReferenceAsBytes(port));
		s.Send(AsBytes(host));
		socket.ScheduleRead();
	}

private:
	void OnSocketReady([[maybe_unused]] unsigned events) noexcept try {
		ReceiveMessageBuffer<1, CMSG_SPACE(sizeof(int) * 1)> rbuf;
		auto r = ReceiveMessage(socket.GetSocket(), rbuf, 0);
		if (r.fds.size() != 1)
			throw std::runtime_error{"Bad number of fds"};

		handler.OnSocketConnectSuccess(UniqueSocketDescriptor{r.fds.front().Release()});
		delete this;
	} catch (...) {
		handler.OnSocketConnectError(std::current_exception());
		delete this;
	}

	// virtual methods from class Cancellable
	virtual void Cancel() noexcept override {
		delete this;
	}
};

static void
NsResolveConnectTCP(EventLoop &event_loop,
		    SpawnService &spawn_service, const ChildOptions &options,
		    std::string_view host, const unsigned port,
		    ConnectSocketHandler &handler,
		    CancellablePointer &cancel_ptr)
{
	auto [control_socket, child_handle] =
		SpawnNsResolveConnectTCPFunction(spawn_service, options);

	auto *operation = new SpawnResolveConnectOperation(event_loop, std::move(control_socket),
							   std::move(child_handle),
							   handler);
	operation->Start(host, port, cancel_ptr);
}

#endif // ENABLE_TRANSLATION

class ResolveConnectOperation final
	: ConnectSocketHandler,
#ifdef HAVE_NLOHMANN_JSON
	  Systemd::ResolveHostnameHandler,
#endif
	  Cancellable
{
#ifdef HAVE_NLOHMANN_JSON
	CancellablePointer resolve;
#endif

	ConnectSocket connect;

	ConnectSocketHandler &handler;

public:
	ResolveConnectOperation(EventLoop &event_loop,
				ConnectSocketHandler &_handler) noexcept
		:connect(event_loop, *this),
		 handler(_handler) {}

	auto &GetEventLoop() const noexcept {
		return connect.GetEventLoop();
	}

	void Start(std::string_view host, unsigned port,
		   CancellablePointer &cancel_ptr) noexcept {
		cancel_ptr = *this;

#ifdef HAVE_NLOHMANN_JSON
		Systemd::ResolveHostname(GetEventLoop(), host, port, AF_UNSPEC,
					 *this, resolve);
#else
		/* no systemd support - using the (blocking) standard
		   resolver */
		static constexpr struct addrinfo hints = {
			.ai_flags = AI_ADDRCONFIG,
			.ai_family = AF_UNSPEC,
			.ai_socktype = SOCK_STREAM,
		};

		const auto r = Resolve(std::string{host}.c_str(), port, &hints);
		connect.Connect(r.GetBest(), std::chrono::seconds{60});
#endif
	}

private:
#ifdef HAVE_NLOHMANN_JSON
	// virtual methods from class Systemd::ResolveHostnameHandler
	void OnResolveHostname(std::span<const SocketAddress> address) noexcept override {
		resolve = {};
		// TODO use the other addresses as fallback?
		connect.Connect(address.front(), std::chrono::seconds{60});
	}

	void OnResolveHostnameError(std::exception_ptr error) noexcept override {
		auto &_handler = handler;
		delete this;
		_handler.OnSocketConnectError(std::move(error));
	}
#endif // HAVE_NLOHMANN_JSON

	// virtual methods from class ConnectSocketHandler
	void OnSocketConnectSuccess(UniqueSocketDescriptor fd) noexcept override {
		auto &_handler = handler;
		delete this;
		_handler.OnSocketConnectSuccess(std::move(fd));
	}

	void OnSocketConnectError(std::exception_ptr error) noexcept override {
		auto &_handler = handler;
		delete this;
		_handler.OnSocketConnectError(std::move(error));
	}

	// virtual methods from class Cancellable
	virtual void Cancel() noexcept override {
#ifdef HAVE_NLOHMANN_JSON
		if (resolve)
			resolve.Cancel();
#endif // HAVE_NLOHMANN_JSON

		delete this;
	}
};

void
ResolveConnectTCP(const Connection &ssh_connection,
		  std::string_view host, unsigned port,
		  ConnectSocketHandler &handler,
		  CancellablePointer &cancel_ptr) noexcept
{
#ifdef ENABLE_TRANSLATION
	if (const auto *tr = ssh_connection.GetTranslationResponse()) {
		// TODO switch uid/gid?

		if (tr->child_options.ns.network_namespace != nullptr)
			return NsResolveConnectTCP(ssh_connection.GetEventLoop(),
						   ssh_connection.GetSpawnService(),
						   tr->child_options,
						   host, port,
						   handler, cancel_ptr);
	}
#endif // ENABLE_TRANSLATION

	auto *operation = new ResolveConnectOperation(ssh_connection.GetEventLoop(), handler);
	operation->Start(host, port, cancel_ptr);
}
