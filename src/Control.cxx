// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Instance.hxx"
#include "Listener.hxx"
#include "net/SocketAddress.hxx"
#include "util/DeleteDisposer.hxx"
#include "util/SpanCast.hxx"

#ifdef HAVE_AVAHI
#include "lib/avahi/Publisher.hxx"
#endif

void
Instance::OnControlPacket([[maybe_unused]] BengControl::Server &control_server,
			  BengControl::Command command,
			  std::span<const std::byte> payload,
			  [[maybe_unused]] std::span<UniqueFileDescriptor> fds,
			  [[maybe_unused]] SocketAddress address, int uid)
{
	using namespace BengControl;

	/* only local clients are allowed to use most commands */
	const bool is_privileged = uid >= 0;

	switch (command) {
	case Command::NOP:
		/* duh! */
		break;

	case Command::TCACHE_INVALIDATE:
	case Command::DUMP_POOLS:
	case Command::ENABLE_NODE:
	case Command::FADE_NODE:
	case Command::NODE_STATUS:
	case Command::STATS:
		break;

	case Command::VERBOSE:
		if (is_privileged && payload.size() == 1)
			SetLogLevel(*(const uint8_t *)payload.data());
		break;

	case Command::FADE_CHILDREN:
		break;

	case Command::DISABLE_ZEROCONF:
#ifdef HAVE_AVAHI
		if (is_privileged && avahi_publisher)
			avahi_publisher->HideServices();
#endif
		break;

	case Command::ENABLE_ZEROCONF:
#ifdef HAVE_AVAHI
		if (is_privileged && avahi_publisher)
			avahi_publisher->ShowServices();
#endif
		break;

	case Command::FLUSH_NFS_CACHE:
	case Command::FLUSH_FILTER_CACHE:
	case Command::STOPWATCH_PIPE:
	case Command::DISCARD_SESSION:
	case Command::FLUSH_HTTP_CACHE:
	case Command::ENABLE_QUEUE:
	case Command::DISABLE_QUEUE:
	case Command::RELOAD_STATE:
		break;

	case Command::TERMINATE_CHILDREN:
#ifdef ENABLE_TRANSLATION
		if (payload.empty())
			break;

		for (auto &i : listeners)
			i.TerminateChildren(ToStringView(payload));
#endif // ENABLE_TRANSLATION
		break;
	}
}

void
Instance::OnControlError(std::exception_ptr error) noexcept
{
	logger(1, error);
}
