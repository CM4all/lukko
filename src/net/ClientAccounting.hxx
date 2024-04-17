// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "event/FarTimerEvent.hxx"
#include "util/IntrusiveHashSet.hxx"
#include "util/IntrusiveList.hxx"

#include <cstdint>

class SocketAddress;
class PerClientAccounting;
class ClientAccountingMap;

class AccountedClientConnection {
	friend class PerClientAccounting;

	IntrusiveListHook<IntrusiveHookMode::NORMAL> siblings;

	PerClientAccounting *per_client = nullptr;

public:
	using List = IntrusiveList<
		AccountedClientConnection,
		IntrusiveListMemberHookTraits<&AccountedClientConnection::siblings>,
		IntrusiveListOptions{.constant_time_size = true}>;

	AccountedClientConnection() = default;
	~AccountedClientConnection() noexcept;

	AccountedClientConnection(const AccountedClientConnection &) = delete;
	AccountedClientConnection &operator=(const AccountedClientConnection &) = delete;
};

class PerClientAccounting final
	: public IntrusiveHashSetHook<IntrusiveHookMode::AUTO_UNLINK>
{
	friend class ClientAccountingMap;

	ClientAccountingMap &map;

	const uint_least64_t address;

	struct GetKey {
		constexpr uint_least64_t operator()(const PerClientAccounting &item) const noexcept {
			return item.address;
		}
	};

	using ConnectionList = AccountedClientConnection::List;

	ConnectionList connections;

	Event::TimePoint expires;

public:
	PerClientAccounting(ClientAccountingMap &_map, uint_least64_t _address) noexcept;

	[[gnu::pure]]
	bool Check() const noexcept;

	void AddConnection(AccountedClientConnection &c) noexcept;
	void RemoveConnection(AccountedClientConnection &c) noexcept;

private:
	[[gnu::pure]]
	Event::TimePoint Now() const noexcept;
};

class ClientAccountingMap {
	const std::size_t max_connections;

	using Map = IntrusiveHashSet<PerClientAccounting, 16384,
				     IntrusiveHashSetOperators<PerClientAccounting,
							       PerClientAccounting::GetKey,
							       std::hash<uint_least64_t>,
							       std::equal_to<uint_least64_t>>>;
	Map map;

	FarTimerEvent cleanup_timer;

public:
	ClientAccountingMap(EventLoop &event_loop, std::size_t _max_connections) noexcept
		:max_connections(_max_connections),
		 cleanup_timer(event_loop, BIND_THIS_METHOD(OnCleanupTimer)) {}

	auto &GetEventLoop() const noexcept {
		return cleanup_timer.GetEventLoop();
	}

	std::size_t GetMaxConnections() const noexcept {
		return max_connections;
	}

	PerClientAccounting *Get(SocketAddress address) noexcept;

	void ScheduleCleanup() noexcept;

private:
	void OnCleanupTimer() noexcept;
};
