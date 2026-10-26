// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "util/IntrusiveHashSet.hxx"
#include "util/SharedLease.hxx"

#include <cstddef>
#include <cstdint>
#include <string>

/**
 * Data accounted for each user.
 */
struct PerUserData {
	/**
	 * The maximum number of ptys a user may allocate (in all of
	 * its connections).  This prevents one user from exhausting
	 * the host's pty pool.
	 */
	static constexpr uint_least16_t MAX_PTYS = 20;

	/**
	 * The current number of ptys, used by #SessionChannel.
	 */
	uint_least16_t n_ptys = 0;
};

/**
 * Adapter between #PerUserData and #SharedAnchor for insertion into
 * #UserAccountingMap.
 */
class PerUserAccounting final
	: public IntrusiveHashSetHook<>,
	  public PerUserData,
	  public SharedAnchor
{
	const std::string name;

	~PerUserAccounting() noexcept = default;

public:
	explicit constexpr PerUserAccounting(std::string_view _name) noexcept
		:name(_name) {}

	PerUserAccounting(const PerUserAccounting &) = delete;
	PerUserAccounting &operator=(const PerUserAccounting &) = delete;

	struct GetKey {
		constexpr std::string_view operator()(const PerUserAccounting &pu) const noexcept {
			return pu.name;
		}
	};

	struct Hash {
		constexpr std::size_t operator()(std::string_view s) const noexcept;
	};

protected:
	// virtual methods from SharedAnchor
	virtual void OnAbandoned() noexcept override {
		unlink();
		delete this;
	}
};

/**
 * A lease for a #PerUserData.
 */
class PerUserAccountingLease {
	SharedLease lease;

public:
	constexpr PerUserAccountingLease() noexcept = default;
	explicit constexpr PerUserAccountingLease(PerUserAccounting &pu) noexcept
		:lease(pu) {}

	explicit constexpr operator bool() const noexcept {
		return static_cast<bool>(lease);
	}

	constexpr PerUserData &operator*() const noexcept {
		return static_cast<PerUserAccounting &>(lease.GetAnchor());
	}

	constexpr PerUserData *operator->() const noexcept {
		return &operator*();
	}
};

/**
 * Manages a #PerUserData instance for each user name.  Objects are
 * freed automatically when the last #PerUserAccountingLease is
 * destructed.
 */
class UserAccountingMap {
	using Map = IntrusiveHashSet<PerUserAccounting, 1024,
				     IntrusiveHashSetOperators<PerUserAccounting,
							       PerUserAccounting::GetKey,
							       PerUserAccounting::Hash,
							       std::equal_to<std::string_view>>>;
	Map map;

public:
	PerUserAccountingLease operator[](std::string_view name) noexcept;
};
