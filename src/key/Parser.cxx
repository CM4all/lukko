// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Parser.hxx"
#include "Ed25519Key.hxx"
#include "ssh/Deserializer.hxx"
#include "lib/sodium/Base64.hxx"
#include "util/AllocatedArray.hxx"
#include "util/SpanCast.hxx"
#include "util/StringCompare.hxx"
#include "util/StringStrip.hxx"
#include "config.h"

#ifdef HAVE_OPENSSL
#include "key/RSAKey.hxx"
#include "key/ECDSAKey.hxx"
#include "openssl/DeserializeEC.hxx"
#include "openssl/DeserializeRSA.hxx"
#include "lib/openssl/Error.hxx"
#endif

using std::string_view_literals::operator""sv;

static constexpr auto openssh_key_v1_magic = "openssh-key-v1\0"sv;
static constexpr auto begin_openssh_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----"sv;
static constexpr auto end_openssh_private_key = "-----END OPENSSH PRIVATE KEY-----"sv;

[[gnu::pure]]
static bool
StartsWith(std::span<const std::byte> &s, std::string_view prefix) noexcept
{
	return s.size() >= prefix.size() &&
		ToStringView(s.first(prefix.size())) == prefix;
}

static bool
SkipPrefix(std::span<const std::byte> &s, std::string_view prefix) noexcept
{
	const bool match = StartsWith(s, prefix);
	if (match)
		s = s.subspan(prefix.size());
	return match;
}

/**
 * Parse a SSH-Agent key.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04
 */
static std::unique_ptr<SecretKey>
ParseSSHAgentKey(SSH::Deserializer &d)
{
	//SSH::Deserializer d{src};
	const auto key_type = d.ReadString();

	if (key_type == "ssh-ed25519"sv) {
		const auto public_key = d.ReadLengthEncoded();
		const auto secret_key = d.ReadLengthEncoded();
		if (public_key.size() != 32 || secret_key.size() != 64)
			throw std::invalid_argument{"Malformed ed25519 key"};

		return std::make_unique<Ed25519Key>(public_key.first<32>(),
						    secret_key.first<64>());
#ifdef HAVE_OPENSSL
	} else if (key_type == "ssh-rsa"sv) {
		const auto n = d.ReadLengthEncoded();
		const auto e = d.ReadLengthEncoded();
		const auto d_ = d.ReadLengthEncoded();
		const auto iqmp = d.ReadLengthEncoded();
		const auto p = d.ReadLengthEncoded();
		const auto q = d.ReadLengthEncoded();

		return std::make_unique<RSAKey>(DeserializeRSA(n, e, d_, iqmp, p, q));
	} else if (key_type == "ecdsa-sha2-nistp256"sv) {
		const auto ecdsa_curve_name = d.ReadString();
		if (ecdsa_curve_name != "nistp256"sv)
			throw std::invalid_argument{"Unsupported ECDSA curve"};

		constexpr std::string_view curve_name = "P-256";

		const auto q = d.ReadLengthEncoded();
		const auto d_ = d.ReadLengthEncoded();

		return std::make_unique<ECDSAKey>(DeserializeEC(curve_name, q, d_));
#endif // HAVE_OPENSSL
	} else
		throw std::invalid_argument{"Unsupported key type"};
}

static std::unique_ptr<SecretKey>
ParseOpenSSHV1PrivateKeys(std::span<const std::byte> src)
{
	SSH::Deserializer d{src};

	const auto check1 = d.ReadU32();
	const auto check2 = d.ReadU32();
	if (check1 != check2)
		throw std::invalid_argument{"Malformed private key"};

	return ParseSSHAgentKey(d);
}

static std::unique_ptr<SecretKey>
ParseOpenSSHV1(std::span<const std::byte> src)
{
	SSH::Deserializer d{src};

	if (const auto ciphername = d.ReadString(); ciphername != "none"sv)
		throw std::invalid_argument{"Encrypted keys not supported"};

	if (const auto kdfname = d.ReadString(); kdfname != "none"sv)
		throw std::invalid_argument{"Encrypted keys not supported"};

	if (const auto kdfoptions = d.ReadString(); !kdfoptions.empty())
		throw std::invalid_argument{"Encrypted keys not supported"};

	const uint_least64_t n_keys = d.ReadU32();

	// skip public keys
	for (uint_least64_t i = 0; i < n_keys; ++i)
		d.ReadLengthEncoded();

	const auto private_keys = d.ReadLengthEncoded();
	return ParseOpenSSHV1PrivateKeys(private_keys);
}

static std::unique_ptr<SecretKey>
ParseOpenSSHBase64PrivateKey(std::string_view src)
{
	src = Strip(src);
	if (!RemoveSuffix(src, end_openssh_private_key))
		throw std::invalid_argument{"OpenSSH base64 trailer not found"};

	auto bin = DecodeBase64IgnoreWhitespace(src);
	if (bin == nullptr)
		throw std::invalid_argument{"base64 decoding failed"};

	return ParseSecretKey(bin);
}

std::unique_ptr<PublicKey>
ParsePublicKeyBlob(std::span<const std::byte> src)
try {
	SSH::Deserializer d{src};
	const auto algorithm = d.ReadString();

	if (algorithm == "ssh-ed25519"sv) {
		const auto public_key = d.ReadLengthEncoded();
		if (public_key.size() != 32)
			throw std::invalid_argument{"Malformed ed25519 key"};

		std::array<std::byte, 64> fake_secret_key{};

		return std::make_unique<Ed25519Key>(public_key.first<32>(),
						    fake_secret_key);
#ifdef HAVE_OPENSSL
	} else if (algorithm == "ssh-rsa"sv) {
		const auto e = d.ReadLengthEncoded();
		const auto n = d.ReadLengthEncoded();

		return std::make_unique<RSAKey>(DeserializeRSAPublic(e, n));
#endif // HAVE_OPENSSL
	} else
		throw std::invalid_argument{"Unsupported key algorithm"};
} catch (SSH::MalformedPacket) {
	throw std::invalid_argument{"Malformed key file"};
}

std::unique_ptr<SecretKey>
ParseSecretKey(std::span<const std::byte> src)
try {
	if (SkipPrefix(src, openssh_key_v1_magic))
		return ParseOpenSSHV1(src);
	else if (SkipPrefix(src, begin_openssh_private_key))
		return ParseOpenSSHBase64PrivateKey(ToStringView(src));
	else
		throw std::invalid_argument{"Unrecognized key format"};
} catch (SSH::MalformedPacket) {
	throw std::invalid_argument{"Malformed key file"};
}
