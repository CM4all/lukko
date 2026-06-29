// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "event/FarTimerEvent.hxx"
#include "net/BareInetAddress.hxx"
#include "util/IntrusiveHashSet.hxx"
#include "util/IntrusiveList.hxx"
#include "util/TokenBucket.hxx"

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

	PerClientAccounting *GetPerClient() const noexcept {
		return per_client;
	}

	void UpdateTokenBucket(double size) noexcept;

	[[gnu::pure]]
	Event::Duration GetDelay() const noexcept;
};

class PerClientAccounting final
	: public IntrusiveHashSetHook<IntrusiveHookMode::AUTO_UNLINK>
{
	friend class ClientAccountingMap;

	ClientAccountingMap &map;

	const BareInetAddress address;

	struct GetKey {
		constexpr const BareInetAddress &operator()(const PerClientAccounting &item) const noexcept {
			return item.address;
		}
	};

	struct Hash {
		[[gnu::pure]]
		std::size_t operator()(const BareInetAddress &_address) const noexcept {
			return _address.Hash();
		}
	};

	using ConnectionList = AccountedClientConnection::List;

	ConnectionList connections;

	Event::TimePoint expires;

	/**
	 * After this time point, the delay can be cleared.
	 */
	Event::TimePoint tarpit_until;

	/**
	 * The current delay (for the server greeting and
	 * authentication).
	 */
	Event::Duration delay{};

	TokenBucket token_bucket;

public:
	PerClientAccounting(ClientAccountingMap &_map, const BareInetAddress &_address) noexcept;

	[[gnu::pure]]
	bool Check() const noexcept;

	void AddConnection(AccountedClientConnection &c) noexcept;
	void RemoveConnection(AccountedClientConnection &c) noexcept;

	void UpdateTokenBucket(double size) noexcept;

	Event::Duration GetDelay() const noexcept {
		return delay;
	}

private:
	[[gnu::pure]]
	Event::TimePoint Now() const noexcept;
};

class ClientAccountingMap {
	const std::size_t max_connections;

	const bool tarpit;

	using Map = IntrusiveHashSet<PerClientAccounting, 16384,
				     IntrusiveHashSetOperators<PerClientAccounting,
							       PerClientAccounting::GetKey,
							       PerClientAccounting::Hash,
							       std::equal_to<BareInetAddress>>>;
	Map map;

	FarTimerEvent cleanup_timer;

public:
	ClientAccountingMap(EventLoop &event_loop, std::size_t _max_connections,
			    bool _tarpit) noexcept
		:max_connections(_max_connections),
		 tarpit(_tarpit),
		 cleanup_timer(event_loop, BIND_THIS_METHOD(OnCleanupTimer)) {}

	auto &GetEventLoop() const noexcept {
		return cleanup_timer.GetEventLoop();
	}

	std::size_t GetMaxConnections() const noexcept {
		return max_connections;
	}

	bool HasTarpit() const noexcept {
		return tarpit;
	}

	PerClientAccounting *Get(SocketAddress address) noexcept;

	void ScheduleCleanup() noexcept;

private:
	void OnCleanupTimer() noexcept;
};
