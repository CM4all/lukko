// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SessionChannel.hxx"
#include "Connection.hxx"
#include "Listener.hxx"
#include "DebugMode.hxx"
#include "spawn/Interface.hxx"
#include "spawn/Mount.hxx"
#include "spawn/Prepared.hxx"
#include "spawn/ProcessHandle.hxx"
#include "spawn/CoEnqueue.hxx"
#include "spawn/CoWaitSpawnCompletion.hxx"
#include "ssh/Deserializer.hxx"
#include "ssh/CConnection.hxx"
#include "ssh/TerminalMode.hxx"
#include "lib/fmt/ExceptionFormatter.hxx"
#include "co/Task.hxx"
#include "system/Error.hxx"
#include "net/ToString.hxx"
#include "io/FdHolder.hxx"
#include "io/Pipe.hxx"
#include "util/SpanCast.hxx"
#include "util/StringAPI.hxx"
#include "util/StringCompare.hxx"
#include "AllocatorPtr.hxx"

#ifdef ENABLE_TRANSLATION
#include "translation/Response.hxx"
#include "io/Open.hxx" // for OpenPath()
#include <forward_list>
#endif // ENABLE_TRANSLATION

#include <fmt/core.h>

#include <tuple> // for std::tie()

#include <fcntl.h>
#include <pty.h> // for openpty()
#include <signal.h>
#include <sys/wait.h> // for WCOREDUMP()
#include <unistd.h>
#include <utmp.h> // for login_tty()

using std::string_view_literals::operator""sv;

SessionChannel::SessionChannel(SSH::CConnection &_connection,
			       SSH::ChannelInit init) noexcept
	:SSH::BufferedChannel(_connection, init, RECEIVE_WINDOW),
	 logger(static_cast<Connection &>(GetConnection()).GetLogger()),
	 stdin_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStdinReady)),
	 stdout_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStdoutReady)),
	 stderr_pipe(_connection.GetEventLoop(), BIND_THIS_METHOD(OnStderrReady)),
	 tty(_connection.GetEventLoop(), BIND_THIS_METHOD(OnTtyReady))
{
}

SessionChannel::~SessionChannel() noexcept
{
	stdin_pipe.Close();
	stdout_pipe.Close();
	stderr_pipe.Close();
	tty.Close();
}

void
SessionChannel::CloseIfInactive() noexcept
{
	if (!IsActive())
		Close();
}

/**
 * Creates a pipe that contains the given string and returns the read
 * side.
 */
static UniqueFileDescriptor
MakeStringPipe(std::string_view s)
{
	auto [r, w] = CreatePipe();
	(void)w.Write(AsBytes(s));
	return std::move(r);
}

void
SessionChannel::SetStderrString(std::string_view s)
{
	child = {};
	slave_tty.Close();
	stdin_pipe.Close();
	stdout_pipe.Close();
	stderr_pipe.Close();
	tty.Close();

	stderr_pipe.Open(MakeStringPipe(s).Release());
	if (GetSendWindow() > 0)
		ScheduleRead();
}

void
SessionChannel::SetEnv(std::string_view name, std::string_view value)
{
	/* this integer addition cannot overflow because the packet
           size is limited; the 32 is an arbitrary number to limit the
           number of (tiny) environment variables */
	env_size += name.size() + value.size() + 32;

	if (env_size >= MAX_ENV_SIZE)
		throw SSH::Connection::Disconnect{
			SSH::DisconnectReasonCode::BY_APPLICATION,
			"Environment too large"sv,
		};

	// TODO check if already exists?

	env.emplace_front(fmt::format("{}={}", name, value));
}

void
SessionChannel::OnWindowAdjust(std::size_t nbytes)
{
	if (GetSendWindow() == 0)
		/* re-schedule all read events, because we are now
		   allowed to send data again */
		ScheduleRead();

	Channel::OnWindowAdjust(nbytes);
}

std::size_t
SessionChannel::OnBufferedData(std::span<const std::byte> payload)
{
	if (!stdin_enabled) {
		stdin_deferred = true;
		return 0;
	}

	ssize_t nbytes;

	if (stdin_pipe.IsDefined())
		nbytes = stdin_pipe.GetFileDescriptor().Write(payload);
	else if (tty.IsDefined())
		nbytes = tty.GetFileDescriptor().Write(payload);
	else
		/* do not update receive window if there's no
		   destination */
		return payload.size();

	if (nbytes < 0) {
		const int e = errno;
		if (e == EAGAIN) {
			if (stdin_pipe.IsDefined())
				stdin_pipe.ScheduleWrite();
			else
				tty.ScheduleWrite();

			return 0;
		} else {
			// TODO log error?
			stdin_pipe.Close();
			return payload.size();
		}
	}

	const std::size_t consumed = static_cast<std::size_t>(nbytes);
	if (consumed < payload.size()) {
		if (stdin_pipe.IsDefined())
			stdin_pipe.ScheduleWrite();
		else
			tty.ScheduleWrite();
	}

	if (ConsumeReceiveWindow(consumed) < RECEIVE_WINDOW/ 2)
		SendWindowAdjust(RECEIVE_WINDOW - GetReceiveWindow());

	return consumed;
}

void
SessionChannel::OnBufferedEof()
{
	stdin_pipe.Close();
}

static std::string
LoginShellName(const char *shell) noexcept
{
	const char *slash = strrchr(shell, '/');
	if (slash != nullptr && slash[1] != 0)
		shell = slash + 1;

	return fmt::format("-{}"sv, shell);
}

inline void
SessionChannel::PreparePipes(PreparedChildProcess &p,
			     FdHolder &close_fds)
{
	auto [stdin_r, stdin_w] = CreatePipe();
	auto [stdout_r, stdout_w] = CreatePipe();
	auto [stderr_r, stderr_w] = CreatePipe();

	/* allocate 256 kB for each pipe to maximize
	   throughput */
	constexpr int PIPE_BUFFER_SIZE = 256 * 1024;
	stdout_w.SetPipeCapacity(PIPE_BUFFER_SIZE);
	stdin_w.SetPipeCapacity(PIPE_BUFFER_SIZE);

	p.stdin_fd = close_fds.Insert(std::move(stdin_r));
	p.stdout_fd = close_fds.Insert(std::move(stdout_w));
	p.stderr_fd = close_fds.Insert(std::move(stderr_w));

	stdin_w.SetNonBlocking();
	stdin_pipe.Open(stdin_w.Release());
	stdout_pipe.Open(stdout_r.Release());
	stderr_pipe.Open(stderr_r.Release());
}

inline void
SessionChannel::PrepareHome(AllocatorPtr alloc, PreparedChildProcess &p) noexcept
{
	if (const char *home = p.ToContainerPath(alloc, p.GetHome())) {
		if (!p.HasEnv("HOME"sv))
			p.SetEnv("HOME"sv, home);

		if (p.chdir == nullptr)
			p.chdir = home;
	}
}

Co::Task<void>
SessionChannel::PrepareChildProcess(AllocatorPtr alloc,
				    PreparedChildProcess &p,
				    FdHolder &close_fds,
				    SSH::Service service)
{
	const auto &c = static_cast<Connection &>(GetConnection());

	const std::string_view username = c.GetUsername();
	p.SetEnv("USER", username);
	p.SetEnv("LOGNAME", username);

	if (service == SSH::Service::SSH) {
		const auto peer_address = c.GetPeerAddress();
		const auto local_address = c.GetLocalAddress();
		const auto peer_host = HostToString(peer_address);
		const auto local_host = HostToString(c.GetLocalAddress());

		p.PutEnv(fmt::format("SSH_CLIENT={} {} {}"sv,
				     peer_host, peer_address.GetPort(),
				     local_address.GetPort()));

		p.PutEnv(fmt::format("SSH_CONNECTION={} {} {} {}"sv,
				     peer_host, peer_address.GetPort(),
				     local_host, local_address.GetPort()));

		p.SetEnv("SHELL", c.GetShell());
	}

	co_await c.PrepareChildProcess(p, close_fds, service);

	if (tty.IsDefined()) {
		assert(service == SSH::Service::SSH);

		p.stdin_fd = p.stdout_fd = p.stderr_fd = close_fds.Insert(std::move(slave_tty));
		p.tty = true;
		p.ns.mount.mount_pts = !debug_mode;
	} else {
		PreparePipes(p, close_fds);
	}

	PrepareHome(alloc, p);
}

void
SessionChannel::SpawnChildProcess(AllocatorPtr alloc,
				  PreparedChildProcess &&p)
{
	auto &c = static_cast<Connection &>(GetConnection());
	auto &spawn_service = c.GetSpawnService();

	if (GetSendWindow() > 0)
		ScheduleRead();

	for (const auto &i : env)
		p.PutEnv(i.c_str());

	if (c.GetAuthorizedKeyOptions().home_read_only) {
		p.ns.mount.mounts = Mount::CloneAll(alloc, p.ns.mount.mounts);

		const char *const home = p.GetHome();

		for (auto &i : p.ns.mount.mounts) {
			if (i.type == Mount::Type::BIND && i.IsInSourcePath(home))
				i.writable = false;
		}
	}

	// TODO use a proper process name
	child = spawn_service.SpawnChildProcess("foo", std::move(p));
	child->SetExitListener(*this);
}

#ifdef ENABLE_TRANSLATION

/**
 * Split the command string into command-line parameters.
 *
 * @param strings a container that will hold string allocations for
 * the C string pointers in the #PreparedChildProcess
 */
static void
SplitCmdline(PreparedChildProcess &p, std::forward_list<std::string> &strings,
	     const char *cmd) noexcept
{
	while (true) {
		while (*cmd == ' ')
			++cmd;
		if (*cmd == '\0')
			break;

		auto &s = strings.emplace_front();

		while (*cmd != '\0') {
			char ch = *cmd++;
			if (ch == ' ')
				break;
			else if (ch == '\\') [[unlikely]] {
				if (*cmd == '\0') [[unlikely]] {
					s.push_back(ch);
					break;
				}

				s.push_back(*cmd++);
			} else
				s.push_back(ch);
		}

		p.Append(s.c_str());
	}
}

inline Co::Task<bool>
SessionChannel::ExecRsync(const char *cmd)
{
	assert(StringStartsWith(cmd, "rsync "sv));

	const auto &c = static_cast<Connection &>(GetConnection());
	assert(c.IsRsyncAllowed());

	/* throttle if the spawner is under pressure */
	co_await CoEnqueueSpawner(c.GetSpawnService());

	Allocator alloc;
	FdHolder close_fds;
	PreparedChildProcess p;

	try {
		co_await PrepareChildProcess(alloc, p, close_fds, SSH::Service::RSYNC);
	} catch (...) {
		/* this is probably because the translation server has
		   rejected the rsync execution */
		// TODO log the error?  use it for the SSH response?
		co_return false;
	}

	if (p.exec_path == nullptr)
		throw std::runtime_error{"No EXECUTE"};

	const UniqueFileDescriptor exec_fd = OpenPath(p.exec_path);
	p.exec_fd = exec_fd;

	std::forward_list<std::string> strings;
	SplitCmdline(p, strings, cmd);

	SpawnChildProcess(alloc, std::move(p));

	co_await CoWaitSpawnCompletion{*child};

	EnableStdin();
	co_return true;
}

#endif

inline Co::Task<bool>
SessionChannel::Exec(const char *cmd)
{
	const auto &c = static_cast<Connection &>(GetConnection());
	if (!c.IsExecAllowed()) {
#ifdef ENABLE_TRANSLATION
		if (cmd != nullptr && c.IsRsyncAllowed() &&
		    StringStartsWith(cmd, "rsync --server "sv) &&
		    co_await ExecRsync(cmd))
			co_return true;
#endif

		if (c.IsSftpOnly() && c.GetListener().GetExecRejectStderr()) {
			SetStderrString("Shell access denied (SFTP only).\r\n"sv);
			co_return true;
		}

		co_return false;
	}

	/* throttle if the spawner is under pressure */
	co_await CoEnqueueSpawner(c.GetSpawnService());

	Allocator alloc;
	FdHolder close_fds;
	PreparedChildProcess p;

	co_await PrepareChildProcess(alloc, p, close_fds, SSH::Service::SSH);

	const char *const shell = c.GetShell();

	if (!c.GetAuthorizedKeyOptions().command.empty()) {
		if (cmd != nullptr)
			p.SetEnv("SSH_ORIGINAL_COMMAND"sv, cmd);

		cmd = c.GetAuthorizedKeyOptions().command.c_str();
	}

	std::string login_shell_name;

	if (cmd != nullptr) {
		p.args.push_back(shell);
		p.args.push_back("-c");
		p.args.push_back(cmd);
	} else {
		p.exec_path = shell;
		p.args.push_back((login_shell_name = LoginShellName(shell)).c_str());
	}

	SpawnChildProcess(alloc, std::move(p));

	co_await CoWaitSpawnCompletion{*child};

	EnableStdin();
	co_return true;
}

static void
ApplyTerminalModes(FileDescriptor fd, std::span<const std::byte> src) noexcept
{
	struct termios tio;

	if (tcgetattr(fd.Get(), &tio) < 0)
		return;

	SSH::ParseTerminalModes(tio, src);
	tcsetattr(fd.Get(), TCSANOW, &tio);
}

inline Co::EagerTask<bool>
SessionChannel::StartSftpServer()
{
	const auto &c = static_cast<Connection &>(GetConnection());

	if (tty.IsDefined())
		/* refuse to run SFTP with a pty */
		co_return false;

	/* throttle if the spawner is under pressure */
	co_await CoEnqueueSpawner(c.GetSpawnService());

	UniqueFileDescriptor sftp_server;
	(void)sftp_server.OpenReadOnly("/usr/lib/cm4all/openssh/libexec/sftp-server");

	Allocator alloc;
	FdHolder close_fds;
	PreparedChildProcess p;

	co_await PrepareChildProcess(alloc, p, close_fds,
				     sftp_server.IsDefined() ? SSH::Service::SFTP : SSH::Service::SSH);

	if (sftp_server.IsDefined()) {
		p.exec_fd = sftp_server;
		p.Append("sftp-server");
	} else
		p.Append("/usr/lib/openssh/sftp-server");

	try {
		SpawnChildProcess(alloc, std::move(p));
		co_await CoWaitSpawnCompletion{*child};
		EnableStdin();
		co_return true;
	} catch (...) {
		logger.Fmt(1, "Failed to spawn SFTP server: {}", std::current_exception());

		if (c.GetListener().GetVerboseErrors()) {
			SetStderrString(fmt::format("Failed to spawn SFTP server: {}\r\n",
						    std::current_exception()));
			co_return true;
		}

		co_return false;
	}
}

Co::EagerTask<bool>
SessionChannel::OnRequest(std::string_view request_type,
			  std::span<const std::byte> type_specific)
{
	const auto &c = static_cast<Connection &>(GetConnection());

	logger.Fmt(1, "ChannelRequest {:?}"sv, request_type);

	if (WasStarted())
		/* the program was already started, and there's no
		   point in handling further requests */
		co_return false;

	if (request_type == "exec"sv) {
		SSH::Deserializer d{type_specific};
		const std::string command{d.ReadString()};
		d.ExpectEnd();

		static constexpr std::size_t MAX_LOG_SIZE = 256;
		logger.Fmt(1, "  exec {:?}{}"sv,
			   command.size() > MAX_LOG_SIZE ? command.substr(0, MAX_LOG_SIZE) : command,
			   command.size() > MAX_LOG_SIZE ? "…"sv : ""sv);

		if (command.size() + env_size > MAX_ENV_SIZE) {
			if (c.GetListener().GetExecRejectStderr()) {
				SetStderrString("Command too long\r\n"sv);
				co_return true;
			}

			co_return false;
		}

		try {
			co_return co_await Exec(command.c_str());
		} catch (...) {
			logger.Fmt(1, "Failed to spawn child process: {}", std::current_exception());

			if (c.GetListener().GetVerboseErrors()) {
				SetStderrString(fmt::format("Failed to execute: {}\r\n",
							    std::current_exception()));
				co_return true;
			}

			co_return false;
		}
	} else if (request_type == "shell"sv) {
		try {
			co_return co_await Exec(nullptr);
		} catch (...) {
			logger.Fmt(1, "Failed to spawn shell: {}", std::current_exception());

			if (c.GetListener().GetVerboseErrors()) {
				SetStderrString(fmt::format("Failed to spawn shell: {}\r\n",
							    std::current_exception()));
				co_return true;
			}

			co_return false;
		}
	} else if (request_type == "subsystem"sv) {
		SSH::Deserializer d{type_specific};
		const std::string_view subsystem_name{d.ReadString()};
		d.ExpectEnd();

		logger.Fmt(1, "  subsystem {:?}"sv, subsystem_name);

		if (subsystem_name == "sftp"sv)
			co_return co_await StartSftpServer();
		else
			co_return false;
	} else if (request_type == "pty-req"sv) {
		if (!c.IsExecAllowed() || c.GetAuthorizedKeyOptions().no_pty) {
			if (c.IsSftpOnly() && c.GetListener().GetExecRejectStderr())
				/* fake a positive response (but
				   ignore the request) if this is
				   SFTP-only */
				co_return true;

			co_return false;
		}

		struct winsize ws{};

		SSH::Deserializer d{type_specific};
		const auto term = d.ReadString();
		ws.ws_col = d.ReadU32();
		ws.ws_row = d.ReadU32();
		ws.ws_xpixel = d.ReadU32();
		ws.ws_ypixel = d.ReadU32();
		const auto encoded_terminal_modes = d.ReadLengthEncoded();
		d.ExpectEnd();

		int master, slave;

		if (openpty(&master, &slave, nullptr, nullptr, &ws) < 0)
			throw MakeErrno("openpty() failed");

		slave_tty = UniqueFileDescriptor{AdoptTag{}, slave};
		slave_tty.EnableCloseOnExec();

		tty.Close();
		tty.Open(FileDescriptor{master});
		tty.GetFileDescriptor().EnableCloseOnExec();
		tty.GetFileDescriptor().SetNonBlocking();

		if (!encoded_terminal_modes.empty())
			ApplyTerminalModes(slave_tty, encoded_terminal_modes);

		SetEnv("TERM"sv, term);

		co_return true;
	} else if (request_type == "env"sv) {
		if (!c.IsExecAllowed())
			co_return false;

		SSH::Deserializer d{type_specific};
		const auto name = d.ReadString();
		const auto value = d.ReadString();
		d.ExpectEnd();

		SetEnv(name, value);
		co_return true;
	} else
		co_return false;

	// TOOD "signal"
}

void
SessionChannel::OnWriteBlocked() noexcept
{
	if (GetSendWindow() > 0)
		CancelRead();
}

void
SessionChannel::OnWriteUnblocked() noexcept
{
	if (GetSendWindow() > 0)
		ScheduleRead();
}

void
SessionChannel::OnTtyReady([[maybe_unused]] unsigned events) noexcept
try {
	if (events == PipeEvent::HANGUP) {
		tty.Close();
		MaybeSendEofAndClose();
		return;
	}

	if (events & PipeEvent::WRITE) {
		tty.CancelWrite();
		ReadBuffer();
	}

	if ((events & PipeEvent::READ) == 0)
		return;

	std::byte buffer[4096];
	std::span<std::byte> dest{buffer};

	if (GetSendWindow() < dest.size()) {
		dest = dest.first(GetSendWindow());
		assert(!dest.empty());
	}

	auto nbytes = tty.GetFileDescriptor().Read(dest);
	if (nbytes > 0) {
		SendData(dest.first(nbytes));

		if (GetSendWindow() == 0)
			CancelRead();
	} else {
		tty.Close();
		MaybeSendEofAndClose();
	}
} catch (...) {
	GetConnection().CloseError(std::current_exception());
}

void
SessionChannel::OnStdinReady([[maybe_unused]] unsigned events) noexcept
try {
	stdin_pipe.Cancel();

	ReadBuffer();
} catch (...) {
	GetConnection().CloseError(std::current_exception());
}

void
SessionChannel::OnStdoutReady([[maybe_unused]] unsigned events) noexcept
try {
	std::byte buffer[4096];
	std::span<std::byte> dest{buffer};
	if (GetSendWindow() < dest.size()) {
		dest = dest.first(GetSendWindow());
		assert(!dest.empty());
	}

	auto nbytes = stdout_pipe.GetFileDescriptor().Read(dest);
	if (nbytes > 0) {
		SendData(dest.first(nbytes));

		if (GetSendWindow() == 0)
			CancelRead();
	} else {
		stdout_pipe.Close();
		MaybeSendEofAndClose();
	}
} catch (...) {
	GetConnection().CloseError(std::current_exception());
}

void
SessionChannel::OnStderrReady([[maybe_unused]] unsigned events) noexcept
try {
	std::byte buffer[4096];
	std::span<std::byte> dest{buffer};
	if (GetSendWindow() < dest.size()) {
		dest = dest.first(GetSendWindow());
		assert(!dest.empty());
	}

	auto nbytes = stderr_pipe.GetFileDescriptor().Read(dest);
	if (nbytes > 0) {
		SendStderr(dest.first(nbytes));

		if (GetSendWindow() == 0)
			CancelRead();
	} else {
		stderr_pipe.Close();
		MaybeSendEofAndClose();
	}
} catch (...) {
	GetConnection().CloseError(std::current_exception());
}

void
SessionChannel::OnChildProcessExit(int status) noexcept
try {
	child = {};
	stdin_pipe.Close();

	if (WIFSIGNALED(status)) {
		const char *signal_name = sigdescr_np(WTERMSIG(status));

		SendExitSignal(signal_name != nullptr ? signal_name : "UNKNOWN",
			       WCOREDUMP(status),
			       {});
	} else {
		SendExitStatus(WEXITSTATUS(status));
	}

	CloseIfInactive();
} catch (...) {
	GetConnection().CloseError(std::current_exception());
}
