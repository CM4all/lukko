// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "ZeroconfCluster.hxx"
#include "lib/avahi/Explorer.hxx"
#include "lib/avahi/ExplorerConfig.hxx"
#include "lib/avahi/StringListCast.hxx"
#include "net/AllocatedSocketAddress.hxx"
#include "system/Arch.hxx"
#include "util/djb_hash.hxx"
#include "util/FNVHash.hxx"

#include <algorithm> // for std::sort()
#include <cmath> // for std::log()

using std::string_view_literals::operator""sv;

/**
 * The hash algorithm we use for Rendezvous Hashing.  FNV1a is fast
 * and has just the right properties for a good distribution among all
 * nodes.
 *
 * DJB is inferior when the node addresses are too similar (which is
 * often the case when all nodes are on the same local network) and
 * when the sticky_source is too short (e.g. when database serial
 * numbers are used) due to its small prime (33).
 */
using RendezvousHashAlgorithm = FNV1aAlgorithm<FNVTraits<uint32_t>>;

/**
 * Convert a quasi-random unsigned 64 bit integer to a
 * double-precision float in the range 0..1, preserving as many bits
 * as possible.  The returned value has no arithmetic meaning; the
 * goal of this function is only to convert a hash value to a floating
 * point value.
 */
template<std::unsigned_integral I>
static constexpr double
UintToDouble(const I i) noexcept
{
	constexpr unsigned SRC_BITS = std::numeric_limits<I>::digits;

	/* the mantissa has 53 bits, and this is how many bits we can
	   preserve in the conversion */
	constexpr unsigned DEST_BITS = std::numeric_limits<double>::digits;

	if constexpr (DEST_BITS < SRC_BITS) {
		/* discard upper bits that don't fit into the mantissa */
		constexpr uint_least64_t mask = (~I{}) >> (SRC_BITS - DEST_BITS);
		constexpr double max = I{1} << DEST_BITS;

		return (i & mask) / max;
	} else {
		/* don't discard anything */
		static_assert(std::numeric_limits<uintmax_t>::digits > std::numeric_limits<I>::digits);
		constexpr double max = std::uintmax_t{1} << SRC_BITS;

		return i / max;
	}
}

struct ZeroconfCluster::Member {
	AllocatedSocketAddress address;

	/**
	 * The weight of this node (received in a Zeroconf TXT
	 * record).  We store the negative value because this
	 * eliminates one minus operator from the method
	 * CalculateRendezvousScore().
	 */
	double negative_weight;

	/**
	 * A score for rendezvous hasing calculated from the hash of
	 * the sticky attribute of the current request (e.g. the user
	 * name or account id) and this server address.
	 */
	double rendezvous_score;

	/**
	 * The precalculated hash of #address for Rendezvous
	 * Hashing.
	 */
	uint32_t address_hash;

	Arch arch;

	Member(Arch _arch, double _weight, SocketAddress _address) noexcept
		:address(_address),
		 negative_weight(-_weight),
		 address_hash(RendezvousHashAlgorithm::BinaryHash(address.GetSteadyPart())),
		 arch(_arch) {}

	void Update(SocketAddress _address, Arch _arch, double _weight) noexcept {
		arch = _arch;
		negative_weight = -_weight;
		address = _address;
		address_hash = RendezvousHashAlgorithm::BinaryHash(address.GetSteadyPart());
	}

	void CalculateRendezvousScore(std::span<const std::byte> sticky_source) noexcept {
		const auto rendezvous_hash = RendezvousHashAlgorithm::BinaryHash(sticky_source, address_hash);
		rendezvous_score = negative_weight / std::log(UintToDouble(rendezvous_hash));
	}
};

ZeroconfCluster::ZeroconfCluster(Avahi::Client &client,
				 Avahi::ErrorHandler &error_handler,
				 const Avahi::ServiceExplorerConfig &config)
	:explorer(config.Create(client, *this, error_handler))
{
}

ZeroconfCluster::~ZeroconfCluster() noexcept = default;

inline void
ZeroconfCluster::FillMemberList() noexcept
{
	member_list.clear();
	member_list.reserve(member_map.size());

	for (auto i = member_map.begin(); i != member_map.end(); ++i)
		member_list.push_back(i);
}

SocketAddress
ZeroconfCluster::Pick(Arch arch, std::span<const std::byte> sticky_source) noexcept
{
	if (dirty) {
		dirty = false;
		FillMemberList();
	}

	if (member_list.empty())
		return nullptr;

	for (auto &i : member_list)
		i->second.CalculateRendezvousScore(sticky_source);

	/* sort the all members by a mix of its address hash and the
	   request's hash */
	std::sort(member_list.begin(), member_list.end(),
		  [arch](MemberMap::const_iterator a,
			 MemberMap::const_iterator b) noexcept {
			  if (arch != Arch::NONE &&
			      a->second.arch != b->second.arch) {
				  [[unlikely]]

				  if (a->second.arch == arch)
					  return true;
				  if (b->second.arch == arch)
					  return false;
			  }

			  return a->second.rendezvous_score > b->second.rendezvous_score;
		  });

	return member_list.front()->second.address;
}

[[gnu::pure]]
static Arch
GetArchFromTxt(AvahiStringList *txt) noexcept
{
	constexpr std::string_view prefix = "arch="sv;
	txt = avahi_string_list_find(txt, "arch");
	return txt != nullptr
		? ParseArch(Avahi::ToStringView(*txt).substr(prefix.size()))
		: Arch::NONE;
}

[[gnu::pure]]
static double
GetWeightFromTxt(AvahiStringList *txt) noexcept
{
	constexpr std::string_view prefix = "weight="sv;
	txt = avahi_string_list_find(txt, "weight");
	if (txt == nullptr)
		/* there's no "weight" record */
		return 1.0;

	const char *s = reinterpret_cast<const char *>(txt->text) + prefix.size();
	char *endptr;
	double value = strtod(s, &endptr);
	if (endptr == s || *endptr != '\0' || value <= 0 || value > 1e6)
		/* parser failed: fall back to default value */
		return 1.0;

	return value;
}

void
ZeroconfCluster::OnAvahiNewObject(const std::string &key,
				  SocketAddress address,
				  AvahiStringList *txt) noexcept
{
	const auto arch = GetArchFromTxt(txt);
	const auto weight = GetWeightFromTxt(txt);

	auto [it, inserted] = member_map.try_emplace(key, arch, weight, address);
	if (!inserted) {
		/* update existing member */
		it->second.Update(address, arch, weight);
	}

	dirty = true;
}

void
ZeroconfCluster::OnAvahiRemoveObject(const std::string &key) noexcept
{
	auto i = member_map.find(key);
	if (i == member_map.end())
		return;

	/* TODO: purge entry from the "failure" map, because it
	   will never be used again anyway */

	member_map.erase(i);
	dirty = true;
}
