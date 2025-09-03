// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "AgentForward.hxx"
#include "SocketChannel.hxx"
#include "Connection.hxx"
#include "SessionChannel.hxx"
#include "util/Cancellable.hxx"
#include "util/DeleteDisposer.hxx"

#include <cassert>

using std::string_view_literals::operator""sv;

class AgentForward::Factory final
	: public IntrusiveListHook<IntrusiveHookMode::AUTO_UNLINK>,
	  public SSH::ChannelFactory
{
	Connection &connection;

	SocketEvent socket;

	CancellablePointer cancel_ptr;

public:
	Factory(Connection &_connection,
		UniqueSocketDescriptor &&_socket) noexcept
		:connection(_connection),
		 socket(connection.GetEventLoop(), BIND_THIS_METHOD(OnSocketReady),
			_socket.Release())
	{
		/* detect hangups, but not interested in reading */
		socket.Schedule(EPOLLRDHUP);
	}

	~Factory() noexcept {
		socket.Close();

		if (cancel_ptr)
			cancel_ptr.Cancel();
	}

	void Open() {
		// TODO "auth-agent@openssh.com" or "agent-connect"?
		connection.OpenChannel("auth-agent@openssh.com"sv,
				       SocketChannel::RECEIVE_WINDOW,
				       *this, cancel_ptr);
	}

	/* virtual methods from class SSH::ChannelFactory */
	void SerializeOpen(SSH::Serializer &s) const override;
	std::unique_ptr<SSH::Channel> CreateChannel(SSH::ChannelInit init) override;
	void OnChannelOpenFailure(SSH::ChannelOpenFailureReasonCode code,
				  std::string_view description) noexcept override;

private:
	void OnSocketReady(unsigned) noexcept {
		delete this;
	}
};

void
AgentForward::Factory::SerializeOpen(SSH::Serializer &) const
{
	// no further data in this CHANNEL_OPEN packet
}

std::unique_ptr<SSH::Channel>
AgentForward::Factory::CreateChannel(SSH::ChannelInit init)
{
	assert(cancel_ptr);
	cancel_ptr = {};

	auto &_connection = connection;
	UniqueSocketDescriptor _socket{AdoptTag{}, socket.ReleaseSocket()};
	delete this;
	return std::make_unique<SocketChannel>(_connection, init, std::move(_socket));
}

void
AgentForward::Factory::OnChannelOpenFailure(SSH::ChannelOpenFailureReasonCode code,
					   std::string_view description) noexcept
{
	assert(cancel_ptr);
	cancel_ptr = {};

	connection.GetLogger().Fmt(1, "Peer refused to open 'auth-agent@openssh.com' channel: {} (code {})",
				   description, static_cast<unsigned>(code));

	(void)code;
	delete this;
}

AgentForward::AgentForward(Connection &_connection, SessionChannel &_channel) noexcept
	:ServerSocket(_connection.GetEventLoop()),
	 connection(_connection), channel(_channel)
{
	ServerSocket::Listen(listener.Create(SOCK_STREAM, 16));
}

AgentForward::~AgentForward() noexcept
{
	factories.clear_and_dispose(DeleteDisposer{});
}

void
AgentForward::OnAccept(UniqueSocketDescriptor fd, SocketAddress) noexcept
{
	auto *factory = new Factory(connection, std::move(fd));

	try {
		factory->Open();

		factories.push_back(*factory);
	} catch (...) {
		delete factory;
		connection.GetLogger()(1, std::current_exception());
	}
}

void
AgentForward::OnAcceptError(std::exception_ptr error) noexcept
{
	channel.OnAgentForwardError(std::move(error));
}
