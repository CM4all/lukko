// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "DeserializeRSA.hxx"
#include "DeserializeBN.hxx"
#include "BN.hxx"
#include "lib/openssl/Error.hxx"
#include "util/ScopeExit.hxx"

#include <openssl/core_names.h> // for OSSL_PKEY_PARAM_RSA_*
#include <openssl/param_build.h>

static OSSL_PARAM *
ToParamPublic(const BIGNUM &e, const BIGNUM &n)
{
	OSSL_PARAM_BLD *const bld = OSSL_PARAM_BLD_new();
	if (bld == nullptr)
		throw SslError{};

	AtScopeExit(bld) { OSSL_PARAM_BLD_free(bld); };

	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, &n);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, &e);

	OSSL_PARAM *param = OSSL_PARAM_BLD_to_param(bld);
	if (param == nullptr)
		throw SslError{};

	return param;
}

static OSSL_PARAM *
ToParamPublic(std::span<const std::byte> e,
	      std::span<const std::byte> n)
{
	return ToParamPublic(*DeserializeBIGNUM(e),
			     *DeserializeBIGNUM(n));
}

UniqueEVP_PKEY
DeserializeRSAPublic(std::span<const std::byte> e,
		     std::span<const std::byte> n)
{
	OSSL_PARAM *param = ToParamPublic(e, n);
	AtScopeExit(param) { OSSL_PARAM_free(param); };

	const UniqueEVP_PKEY_CTX ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
	if (!ctx)
		throw SslError{"EVP_PKEY_CTX_new_id() failed"};

	if (EVP_PKEY_fromdata_init(ctx.get()) != 1)
		throw SslError{"EVP_PKEY_fromdata_init() failed"};

	EVP_PKEY *pkey = nullptr;
	if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_KEYPAIR, param) != 1)
		throw SslError{"EVP_PKEY_fromdata() failed"};

	return UniqueEVP_PKEY{pkey};
}

static UniqueBIGNUM<false>
CalcFactorExponent(const BIGNUM &factor, const BIGNUM &d, BN_CTX &ctx)
{
	const auto tmp = BN_sub<false>(factor, *BN_value_one());
	return BN_mod_<false>(d, *tmp, ctx);
}

static OSSL_PARAM *
ToParam(const BIGNUM &n, const BIGNUM &e, const BIGNUM &d,
	const BIGNUM &iqmp,
	const BIGNUM &p, const BIGNUM &q,
	const BIGNUM &dmp, const BIGNUM &dmq)
{
	OSSL_PARAM_BLD *const bld = OSSL_PARAM_BLD_new();
	if (bld == nullptr)
		throw SslError{};

	AtScopeExit(bld) { OSSL_PARAM_BLD_free(bld); };

	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, &n);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, &e);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, &d);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, &p);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, &q);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq);

	OSSL_PARAM *param = OSSL_PARAM_BLD_to_param(bld);
	if (param == nullptr)
		throw SslError{};

	return param;
}

static OSSL_PARAM *
ToParam(const BIGNUM &n, const BIGNUM &e, const BIGNUM &d,
	const BIGNUM &iqmp,
	const BIGNUM &p, const BIGNUM &q)
{
	BN_CTX *const bn_ctx = BN_CTX_new();
	if (bn_ctx == nullptr)
		throw SslError{};

	AtScopeExit(bn_ctx) { BN_CTX_free(bn_ctx); };

	const auto dmp = CalcFactorExponent(d, p, *bn_ctx);
	const auto dmq = CalcFactorExponent(d, q, *bn_ctx);

	return ToParam(n, e, d, iqmp, p, q, *dmp, *dmq);
}

static OSSL_PARAM *
ToParam(std::span<const std::byte> n,
	std::span<const std::byte> e,
	std::span<const std::byte> d,
	std::span<const std::byte> iqmp,
	std::span<const std::byte> p,
	std::span<const std::byte> q)
{
	return ToParam(*DeserializeBIGNUM(n),
		       *DeserializeBIGNUM(e),
		       *DeserializeBIGNUM(d),
		       *DeserializeBIGNUM(iqmp),
		       *DeserializeBIGNUM(p),
		       *DeserializeBIGNUM(q));
}

UniqueEVP_PKEY
DeserializeRSA(std::span<const std::byte> n,
	       std::span<const std::byte> e,
	       std::span<const std::byte> d,
	       std::span<const std::byte> iqmp,
	       std::span<const std::byte> p,
	       std::span<const std::byte> q)
{
	OSSL_PARAM *param = ToParam(n, e, d, iqmp, p, q);
	AtScopeExit(param) { OSSL_PARAM_free(param); };

	const UniqueEVP_PKEY_CTX ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
	if (!ctx)
		throw SslError{"EVP_PKEY_CTX_new_id() failed"};

	if (EVP_PKEY_fromdata_init(ctx.get()) != 1)
		throw SslError{"EVP_PKEY_fromdata_init() failed"};

	EVP_PKEY *pkey = nullptr;
	if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_KEYPAIR, param) != 1)
		throw SslError{"EVP_PKEY_fromdata() failed"};

	return UniqueEVP_PKEY{pkey};
}
