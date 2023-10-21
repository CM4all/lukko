// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SerializeEC.hxx"
#include "ssh/Serializer.hxx"
#include "lib/openssl/Error.hxx"

void
Serialize(SSH::Serializer &s, const EC_POINT &v, const EC_GROUP &g,
	  point_conversion_form_t form)
{
	std::size_t size = EC_POINT_point2oct(&g, &v, form, nullptr, 0, nullptr);
	if (size == 0)
		throw SslError{};

	const auto w = FromBytesStrict<unsigned char>(s.BeginWriteN(size));
	if (!EC_POINT_point2oct(&g, &v, form, w.data(), w.size(), nullptr))
		throw SslError{};

	s.CommitWriteN(size);
}
