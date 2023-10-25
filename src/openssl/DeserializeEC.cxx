// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "DeserializeEC.hxx"
#include "DeserializeBN.hxx"
#include "BN.hxx"
#include "lib/openssl/Error.hxx"
#include "lib/openssl/UniqueBN.hxx"
#include "lib/openssl/UniqueEC.hxx"

#include <openssl/obj_mac.h> // for NID_X9_62_prime_field

static constexpr std::size_t MAX_EC_SIZE = (528 * 2 / 8) + 1;

static void
EC_POINT_oct2point(const EC_GROUP &group, EC_POINT &p, std::span<const std::byte> src)
{
	if (!EC_POINT_oct2point(&group, &p,
				reinterpret_cast<const unsigned char *>(src.data()),
				src.size(), nullptr))
		throw SslError{};
}

static void
DeserializeEC_POINT(const EC_GROUP &group, EC_POINT &p, std::span<const std::byte> src)
{
	if (src.size() > MAX_EC_SIZE)
		throw std::invalid_argument{"EC too large"};

	if (src.empty() || src.front() != std::byte{POINT_CONVERSION_UNCOMPRESSED})
		throw std::invalid_argument{"Unsupported EC format"};

	EC_POINT_oct2point(group, p, src);
}

static UniqueEC_POINT
DeserializeEC_POINT(const EC_GROUP &group, std::span<const std::byte> src)
{
	UniqueEC_POINT p{EC_POINT_new(&group)};
	if (p == nullptr)
		throw SslError{};

	DeserializeEC_POINT(group, *p, src);
	return p;
}

static UniqueBIGNUM<false>
EC_GROUP_get_order(const EC_GROUP &group, BN_CTX *ctx)
{
	auto order = NewUniqueBIGNUM<false>();
	if (!EC_GROUP_get_order(&group, order.get(), ctx))
		throw SslError{};

	return order;
}

static std::pair<UniqueBIGNUM<false>, UniqueBIGNUM<false>>
EC_POINT_get_affine_coordinates_GFp(const EC_GROUP &group, const EC_POINT &p,
				    BN_CTX *ctx)
{
	std::pair<UniqueBIGNUM<false>, UniqueBIGNUM<false>> result{BN_new(), BN_new()};
	if (!result.first || !result.second)
		throw SslError{};

	if (!EC_POINT_get_affine_coordinates_GFp(&group, &p, result.first.get(),
						 result.second.get(), ctx))
		throw SslError{};

	return result;
}

static void
ValidatePublicKey(const EC_GROUP &group, const EC_POINT &p)
{
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(&group)) != NID_X9_62_prime_field)
		throw std::invalid_argument{"Wrong prime field"};

	if (EC_POINT_is_at_infinity(&group, &p))
		throw std::invalid_argument{"Q is infinity"};

	const auto order = EC_GROUP_get_order(group, nullptr);
	const auto x_y = EC_POINT_get_affine_coordinates_GFp(group, p, nullptr);

	const auto min_bits = BN_num_bits(order.get()) / 2;
	if (BN_num_bits(x_y.first.get()) <= min_bits ||
	    BN_num_bits(x_y.second.get()) <= min_bits)
		throw std::invalid_argument{"Not enough bits"};

	UniqueEC_POINT nq{EC_POINT_new(&group)};
	if (!nq)
		throw SslError{};

	if (!EC_POINT_mul(&group, nq.get(), nullptr, &p, order.get(), nullptr))
		throw SslError{};

	if (!EC_POINT_is_at_infinity(&group, nq.get()))
		throw std::invalid_argument{"Not at infinity"};

	const auto tmp = BN_sub<false>(*order, *BN_value_one());
	if (BN_cmp(x_y.first.get(), tmp.get()) >= 0 ||
	    BN_cmp(x_y.second.get(), tmp.get()) >= 0)
		throw std::invalid_argument{"Public key mismatch"};
}

static void
ValidatePrivateKey(const EC_KEY &key)
{
	const EC_GROUP &group = *EC_KEY_get0_group(&key);
	const BIGNUM &private_key = *EC_KEY_get0_private_key(&key);

	const auto order = EC_GROUP_get_order(group, nullptr);

	if (BN_num_bits(&private_key) <= BN_num_bits(order.get()) / 2)
		throw std::invalid_argument{"Not enough bits"};

	const auto tmp = BN_sub<false>(*order, *BN_value_one());
	if (BN_cmp(&private_key, tmp.get()) >= 0)
		throw std::invalid_argument{"Private key mismatch"};
}

UniqueEC_KEY
DeserializeEC(int curve_nid, std::span<const std::byte> q,
	      std::span<const std::byte> d)
{
	UniqueEC_KEY ec{EC_KEY_new_by_curve_name(curve_nid)};
	const EC_GROUP &group = *EC_KEY_get0_group(ec.get());

	auto p = DeserializeEC_POINT(group, q);

	ValidatePublicKey(group, *p);

	if (!EC_KEY_set_public_key(ec.get(), p.get()))
		throw SslError{};

	p.release();

	const auto exponent = DeserializeBIGNUM(d);
	if (!EC_KEY_set_private_key(ec.get(), exponent.get()))
		throw SslError{};

	ValidatePrivateKey(*ec);
	return ec;
}
