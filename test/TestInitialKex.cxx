// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "memory/fb_pool.hxx"
#include "ssh/AwaitableConnection.hxx"
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
