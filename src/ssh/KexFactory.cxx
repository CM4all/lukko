// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "KexFactory.hxx"
#include "KexCurve25519.hxx"
#include "util/IterableSplitString.hxx"

#ifdef HAVE_OPENSSL
#include "KexECDH.hxx"
#endif

using std::string_view_literals::operator""sv;

namespace SSH {

std::unique_ptr<Kex>
MakeKex(std::string_view algorithms)
{
	for (const std::string_view a : IterableSplitString(algorithms, ','))
		if (a == "curve25519-sha256"sv)
			return std::make_unique<Curve25519Kex>();
#ifdef HAVE_OPENSSL
		else if (a == "ecdh-sha2-nistp256"sv)
			return std::make_unique<ECDHKex>();
#endif

	return {};
}

} // namespace SSH
