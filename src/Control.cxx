// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Instance.hxx"
#include "Connection.hxx"
#include "net/SocketAddress.hxx"
#include "util/DeleteDisposer.hxx"
#include "util/PrintException.hxx"
#include "util/SpanCast.hxx"

#ifdef HAVE_AVAHI
#include "lib/avahi/Publisher.hxx"
#endif

using namespace BengProxy;

void
Instance::OnControlPacket([[maybe_unused]] ControlServer &control_server,
			  BengProxy::ControlCommand command,
			  std::span<const std::byte> payload,
			  [[maybe_unused]] std::span<UniqueFileDescriptor> fds,
			  [[maybe_unused]] SocketAddress address, int uid)
{
	/* only local clients are allowed to use most commands */
	const bool is_privileged = uid >= 0;

	switch (command) {
	case ControlCommand::NOP:
		/* duh! */
		break;

	case ControlCommand::TCACHE_INVALIDATE:
	case ControlCommand::DUMP_POOLS:
	case ControlCommand::ENABLE_NODE:
	case ControlCommand::FADE_NODE:
	case ControlCommand::NODE_STATUS:
	case ControlCommand::STATS:
		break;

	case ControlCommand::VERBOSE:
		if (is_privileged && payload.size() == 1)
			SetLogLevel(*(const uint8_t *)payload.data());
		break;

	case ControlCommand::FADE_CHILDREN:
		break;

	case ControlCommand::DISABLE_ZEROCONF:
#ifdef HAVE_AVAHI
		if (is_privileged && avahi_publisher)
			avahi_publisher->HideServices();
#endif
		break;

	case ControlCommand::ENABLE_ZEROCONF:
#ifdef HAVE_AVAHI
		if (is_privileged && avahi_publisher)
			avahi_publisher->ShowServices();
#endif
		break;

	case ControlCommand::FLUSH_NFS_CACHE:
	case ControlCommand::FLUSH_FILTER_CACHE:
	case ControlCommand::STOPWATCH_PIPE:
	case ControlCommand::DISCARD_SESSION:
	case ControlCommand::FLUSH_HTTP_CACHE:
		break;

	case ControlCommand::TERMINATE_CHILDREN:
#ifdef ENABLE_TRANSLATION
		if (payload.empty())
			break;

		connections.remove_and_dispose_if([tag = ToStringView(payload)](const Connection &c){
			return c.HasTag(tag);
		}, [](Connection *c){
			c->Terminate();
		});
#endif // ENABLE_TRANSLATION
		break;
	}
}

void
Instance::OnControlError(std::exception_ptr error) noexcept
{
	PrintException(error);
}
