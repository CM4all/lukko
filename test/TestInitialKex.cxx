// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "memory/fb_pool.hxx"
#include "ssh/AwaitableConnection.hxx"
#include "ssh/Curve25519.hxx"
#include "ssh/KexProposal.hxx"
#include "ssh/PacketSerializer.hxx"
#include "ssh/Disposer.hxx"
#include "ssh/SimpleHostKeyChooser.hxx"
#include "ssh/SimpleHostKeyVerifier.hxx"
#include "key/Ed25519Key.hxx"
#include "key/List.hxx"
#include "key/Set.hxx"
#include "thread/Pool.hxx"
#include "event/Loop.hxx"
#include "net/SocketPair.hxx"
#include "co/Runner.hxx"

#include <gtest/gtest.h>

#include <optional>

using std::string_view_literals::operator""sv;

namespace {

struct TestConnectionPtr final : SSH::ConnectionDisposer {
	std::optional<SSH::AwaitableConnection> connection;

	/* virtual methods from class SSH::ConnectionDisposer */
	void Dispose([[maybe_unused]] SSH::Connection *_connection) noexcept override {
		assert(connection);
		assert(_connection == &*connection);

		connection.reset();
	}
};

static void
SendPacket(SocketDescriptor s, SSH::PacketSerializer &&p)
{
	const auto src = p.Finish(8, false);
	ASSERT_EQ(s.Write(src), static_cast<ssize_t>(src.size()));
}

static SSH::PacketSerializer
MakeKexInit()
{
	SSH::PacketSerializer s{SSH::MessageNumber::KEXINIT};
	s.WriteZero(16); // cookie
	SerializeProposal(s, {
		.kex_algorithms = "curve25519-sha256"sv,
		.server_host_key_algorithms = "ssh-ed25519"sv,
		.encryption_algorithms_client_to_server = "aes128-ctr"sv,
		.encryption_algorithms_server_to_client = "aes128-ctr"sv,
		.mac_algorithms_client_to_server = "hmac-sha2-256"sv,
		.mac_algorithms_server_to_client = "hmac-sha2-256"sv,
		.compression_algorithms_client_to_server = "none"sv,
		.compression_algorithms_server_to_client = "none"sv,
		.languages_client_to_server = ""sv,
		.languages_server_to_client = ""sv,
	});
	s.WriteBool(false); // first_kex_packet_follows
	s.WriteU32(0); // reserved
	return s;
}

static void
CoRun(EventLoop &event_loop, Co::InvokeTask &&task)
{
	Co::Runner runner;
	runner.Start(std::move(task));
	if (!runner.IsDone())
		event_loop.Run();
	runner.Finish();
}

} // anonymous namespace

TEST(InitialKex, Simple)
{
	const ScopeFbPoolInit fb_pool_init;
	thread_pool_set_volatile();

	auto host_key = std::make_unique<Ed25519Key>(Ed25519Key::Generate{});

	PublicKeySet host_public_keys;
	host_public_keys.Add(*host_key);

	SecretKeyList host_secret_keys;
	host_secret_keys.Add(std::move(host_key));

	const SSH::SimpleHostKeyChooser host_key_chooser{host_secret_keys};
	const SSH::SimpleHostKeyVerifier host_key_verifier{host_public_keys};

	EventLoop event_loop;

	CoRun(event_loop, [&]() -> Co::InvokeTask {
		auto [socket_a, socket_b] = CreateStreamSocketPairNonBlock();

		TestConnectionPtr a, b;
		a.connection.emplace(event_loop, std::move(socket_a), a, host_key_chooser);
		b.connection.emplace(event_loop, std::move(socket_b), b, host_key_verifier);

		co_await a.connection->WaitEncrypted();

		if (b.connection)
			co_await b.connection->WaitEncrypted();
	}());

	thread_pool_stop();
	thread_pool_join();
	thread_pool_deinit();
}

/**
 * A protocol error after the server has sent NEWKEYS (i.e. while its
 * output is encrypted, but its input is not).
 */
TEST(InitialKex, ProtocolErrorAfterNewKeys)
{
	const ScopeFbPoolInit fb_pool_init;
	thread_pool_set_volatile();

	SecretKeyList host_secret_keys;
	host_secret_keys.Add(std::make_unique<Ed25519Key>(Ed25519Key::Generate{}));

	const SSH::SimpleHostKeyChooser host_key_chooser{host_secret_keys};

	EventLoop event_loop;

	/* outside of the coroutine frame, because the coroutine
	   finishes inside the AwaitableConnection destructor */
	TestConnectionPtr a;

	CoRun(event_loop, [&]() -> Co::InvokeTask {
		auto [socket_a, client] = CreateStreamSocketPairNonBlock();

		a.connection.emplace(event_loop, std::move(socket_a), a, host_key_chooser);

		Curve25519Scalar secret_key;
		secret_key.fill(std::byte{0x42});
		Curve25519 public_key;
		Curve25519SecretKeyToPublicKey(secret_key, public_key);

		const auto version = "SSH-2.0-Test\r\n"sv;
		EXPECT_EQ(client.Write(AsBytes(version)), static_cast<ssize_t>(version.size()));

		SendPacket(client, MakeKexInit());

		SSH::PacketSerializer ecdh_init{SSH::MessageNumber::ECDH_KEX_INIT};
		ecdh_init.WriteLengthEncoded(public_key);
		SendPacket(client, std::move(ecdh_init));

		/* unexpected second KEXINIT */
		SendPacket(client, MakeKexInit());

		co_await a.connection->WaitDisconnect();
	}());

	thread_pool_stop();
	thread_pool_join();
	thread_pool_deinit();
}
