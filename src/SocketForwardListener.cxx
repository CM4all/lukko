// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SocketForwardListener.hxx"
#include "SocketChannel.hxx"
#include "Connection.hxx"
#include "ssh/Serializer.hxx"
#include "net/ToString.hxx"
#include "util/Cancellable.hxx"
#include "util/DeleteDisposer.hxx"

#include <cassert>

using std::string_view_literals::operator""sv;

class SocketForwardListener::Factory final
	: public IntrusiveListHook<IntrusiveHookMode::AUTO_UNLINK>,
	  public SSH::ChannelFactory
{
	Connection &connection;

	SocketEvent socket;

	CancellablePointer cancel_ptr;

	const std::string bind_address, peer_address;
	const uint_least32_t bind_port, peer_port;

public:
	Factory(Connection &_connection,
		std::string_view _bind_address,
		uint_least32_t _bind_port,
		UniqueSocketDescriptor _socket,
		SocketAddress _peer_address) noexcept
		:connection(_connection),
		 socket(connection.GetEventLoop(), BIND_THIS_METHOD(OnSocketReady),
			_socket.Release()),
		 bind_address(_bind_address),
		 peer_address(HostToString(_peer_address)),
		 bind_port(_bind_port),
		 peer_port(_peer_address.GetPort())
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
		connection.OpenChannel("forwarded-tcpip"sv,
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
SocketForwardListener::Factory::SerializeOpen(SSH::Serializer &s) const
{
	s.WriteString(bind_address);
	s.WriteU32(bind_port);
	s.WriteString(peer_address);
	s.WriteU32(peer_port);
}

std::unique_ptr<SSH::Channel>
SocketForwardListener::Factory::CreateChannel(SSH::ChannelInit init)
{
	assert(cancel_ptr);
	cancel_ptr = {};

	auto &_connection = connection;
	UniqueSocketDescriptor _socket{AdoptTag{}, socket.ReleaseSocket()};
	delete this;
	return std::make_unique<SocketChannel>(_connection, init, std::move(_socket));
}

void
SocketForwardListener::Factory::OnChannelOpenFailure(SSH::ChannelOpenFailureReasonCode code,
					   std::string_view description) noexcept
{
	assert(cancel_ptr);
	cancel_ptr = {};

	connection.GetLogger().Fmt(1, "Peer refused to open 'forwarded-tcpip' channel: {} (code {})",
				   description, static_cast<unsigned>(code));

	(void)code;
	delete this;
}

SocketForwardListener::SocketForwardListener(Connection &_connection,
					     std::string &&_bind_address,
					     uint_least32_t _bind_port,
					     UniqueSocketDescriptor _socket) noexcept
	:ServerSocket(_connection.GetEventLoop(),
		      std::move(_socket)),
	 connection(_connection),
	 bind_address(std::move(_bind_address)),
	 bind_port(_bind_port)
{
}

SocketForwardListener::~SocketForwardListener() noexcept
{
	factories.clear_and_dispose(DeleteDisposer{});
}

void
SocketForwardListener::OnAccept(UniqueSocketDescriptor fd,
				SocketAddress address) noexcept
{
	auto *factory = new Factory(connection, bind_address, bind_port,
				    std::move(fd), address);

	try {
		factory->Open();

		factories.push_back(*factory);
	} catch (...) {
		delete factory;
		connection.GetLogger()(1, std::current_exception());
	}
}

void
SocketForwardListener::OnAcceptError(std::exception_ptr error) noexcept
{
	connection.GetLogger()(1, error);
}
