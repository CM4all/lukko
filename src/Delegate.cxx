// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Delegate.hxx"
#include "Connection.hxx"
#include "spawn/CoEnqueue.hxx"
#include "spawn/CoWaitSpawnCompletion.hxx"
#include "spawn/Interface.hxx"
#include "spawn/Prepared.hxx"
#include "spawn/ProcessHandle.hxx"
#include "event/AwaitableSocketEvent.hxx"
#include "net/EasyMessage.hxx"
#include "net/SocketError.hxx"
#include "net/SocketPair.hxx"
#include "net/SocketProtocolError.hxx"
#include "net/LocalSocketAddress.hxx"
#include "io/FdHolder.hxx"
#include "io/Open.hxx"
#include "io/UniqueFileDescriptor.hxx"
#include "co/Task.hxx"
#include "util/SpanCast.hxx"
#include "AllocatorPtr.hxx"

static void ReceivePath(SocketDescriptor control, std::span<char> path) {
	auto nbytes = control.Receive(std::as_writable_bytes(path));
	if (nbytes < 0)
		throw MakeSocketError("Failed to receive");

	if (nbytes == 0)
		throw SocketClosedPrematurelyError{};

	if (static_cast<std::size_t>(nbytes) >= path.size())
		throw SocketBufferFullError{};

	path[nbytes] = 0;
}

static int
LocalConnectExec(PreparedChildProcess &&)
{
	SocketDescriptor control{3};
	char path[4096];
	ReceivePath(control, path);
	try {
		UniqueSocketDescriptor sock;
		if (!sock.Create(AF_UNIX, SOCK_STREAM, 0)) {
			throw MakeErrno("Could not create unix domain socket");
		}

		const LocalSocketAddress addr(path);
		if (!sock.Connect(addr)) {
			throw MakeErrno("Could not connect to unix domain socket");
		}

		EasySendMessage(control, sock.ToFileDescriptor());
	} catch (...) {
		EasySendError(control, std::current_exception());
	}
	return 0;
}

static int
OpenExec(PreparedChildProcess &&)
{
	SocketDescriptor control{3};
	char path[4096];
	ReceivePath(control, path);
	try {
		auto fd = OpenReadOnly(path);
		EasySendMessage(control, fd);
	} catch (...) {
		EasySendError(control, std::current_exception());
	}
	return 0;
}

[[nodiscard]]
static Co::Task<std::pair<UniqueSocketDescriptor, std::unique_ptr<ChildProcessHandle>>>
SpawnOpen(const Connection &ssh_connection,
	  int (*exec_function)(PreparedChildProcess &&p),
	  bool sftp_mode)
{
	// TODO this is a horrible and inefficient kludge
	auto [control_socket, control_socket_for_child] = CreateSocketPair(SOCK_SEQPACKET);

	Allocator alloc;
	FdHolder close_fds;

	PreparedChildProcess p;
	p.exec_function = exec_function;
	p.args.push_back("dummy");

	co_await ssh_connection.PrepareChildProcess(p, close_fds,
						    sftp_mode ? SSH::Service::SFTP : SSH::Service::SSH);

	if (p.chdir == nullptr)
		if (const char *home = p.ToContainerPath(alloc, p.GetHome()))
			p.chdir = home;

	p.control_fd = control_socket_for_child.ToFileDescriptor();

	co_return std::pair{
		std::move(control_socket),
		ssh_connection.GetSpawnService().SpawnChildProcess("connect", std::move(p)),
	};
}

static void
SendOpen(SocketDescriptor s, std::string_view path)
{
	const auto nbytes = s.Send(AsBytes(path));
	if (nbytes < 0)
		throw MakeSocketError("Failed to send");
}

static Co::Task<UniqueFileDescriptor>
Delegate(const Connection &ssh_connection,
	 std::string_view path,
	 int (*exec_function)(PreparedChildProcess &&p),
	 bool sftp_mode)
{
	/* throttle if the spawner is under pressure */
	co_await CoEnqueueSpawner{ssh_connection.GetSpawnService()};

	auto [control_socket, child_handle] =
		co_await SpawnOpen(ssh_connection, exec_function, sftp_mode);

	/* wait for spawner completion and rethrow errors */
	co_await CoWaitSpawnCompletion{*child_handle};

	SendOpen(control_socket, path);

	co_await AwaitableSocketEvent(ssh_connection.GetEventLoop(),
				      control_socket, SocketEvent::READ);

	auto fd = EasyReceiveMessageWithOneFD(control_socket);
	if (!fd.IsDefined())
		throw std::runtime_error{"Bad number of fds"};

	co_return fd;
}

Co::Task<UniqueFileDescriptor>
DelegateOpen(const Connection &ssh_connection, std::string_view path)
{
	// using SFTP mode because this (usually) mounts an empty rootfs; minimalism!
	return Delegate(ssh_connection, path, OpenExec, true);
}

Co::Task<UniqueFileDescriptor>
DelegateLocalConnect(const Connection &ssh_connection, std::string_view path)
{
	/* Don't use SFTP mode because we are most likely interested in connecting
	 * to the sockets that will not be mounted in SFTP mode. */
	return Delegate(ssh_connection, path, LocalConnectExec, false);
}
