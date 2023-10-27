// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "DeserializeEC.hxx"
#include "DeserializeBN.hxx"
#include "lib/openssl/Error.hxx"
#include "lib/openssl/UniqueBN.hxx"
#include "util/ScopeExit.hxx"

#include <openssl/core_names.h> // for OSSL_PKEY_PARAM_*
#include <openssl/param_build.h>

static OSSL_PARAM *
ToParam(std::string_view curve_name,
	std::span<const std::byte> q, const BIGNUM *d)
{
	OSSL_PARAM_BLD *const bld = OSSL_PARAM_BLD_new();
	if (bld == nullptr)
		throw SslError{};

	AtScopeExit(bld) { OSSL_PARAM_BLD_free(bld); };

	OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
					curve_name.data(), curve_name.size());
	OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, q.data(), q.size());

	if (d != nullptr)
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d);

	OSSL_PARAM *param = OSSL_PARAM_BLD_to_param(bld);
	if (param == nullptr)
		throw SslError{};

	return param;
}

UniqueEVP_PKEY
DeserializeECPublic(std::string_view curve_name, std::span<const std::byte> q)
{
	OSSL_PARAM *param = ToParam(curve_name, q, nullptr);
	AtScopeExit(param) { OSSL_PARAM_free(param); };

	const UniqueEVP_PKEY_CTX ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
	if (!ctx)
		throw SslError{"EVP_PKEY_CTX_new_id() failed"};

	if (EVP_PKEY_fromdata_init(ctx.get()) != 1)
		throw SslError{"EVP_PKEY_fromdata_init() failed"};

	EVP_PKEY *pkey = nullptr;
	if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_KEYPAIR, param) != 1)
		throw SslError{"EVP_PKEY_fromdata() failed"};

	return UniqueEVP_PKEY{pkey};
}

UniqueEVP_PKEY
DeserializeEC(std::string_view curve_name, std::span<const std::byte> q,
	      std::span<const std::byte> d)
{
	OSSL_PARAM *param = ToParam(curve_name, q, DeserializeBIGNUM(d).get());
	AtScopeExit(param) { OSSL_PARAM_free(param); };

	const UniqueEVP_PKEY_CTX ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
	if (!ctx)
		throw SslError{"EVP_PKEY_CTX_new_id() failed"};

	if (EVP_PKEY_fromdata_init(ctx.get()) != 1)
		throw SslError{"EVP_PKEY_fromdata_init() failed"};

	EVP_PKEY *pkey = nullptr;
	if (EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_KEYPAIR, param) != 1)
		throw SslError{"EVP_PKEY_fromdata() failed"};

	return UniqueEVP_PKEY{pkey};
}
