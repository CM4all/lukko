// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "SocketChannel.hxx"
#include "Connection.hxx"
#include "ssh/CConnection.hxx"
#include "net/SocketError.hxx"
#include "net/UniqueSocketDescriptor.hxx"

SocketChannel::SocketChannel(SSH::CConnection &_connection,
			     SSH::ChannelInit init,
			     UniqueSocketDescriptor _socket) noexcept
	:SSH::Channel(_connection, init, RECEIVE_WINDOW),
	 socket(_connection.GetEventLoop(), BIND_THIS_METHOD(OnSocketReady),
		_socket.Release())
{
	socket.ScheduleRead();
}

SocketChannel::~SocketChannel() noexcept
{
	socket.Close();
}

void
SocketChannel::OnWindowAdjust(std::size_t nbytes)
{
	if (GetSendWindow() == 0)
		/* re-schedule all read events, because we are now
		   allowed to send data again */
		socket.ScheduleRead();

	Channel::OnWindowAdjust(nbytes);
}

void
SocketChannel::OnData(std::span<const std::byte> payload)
{
	const auto nbytes = socket.GetSocket().WriteNoWait(payload);
	if (nbytes < 0)
		throw MakeSocketError("Failed to send");
	// TODO handle EAGAIN
	// TODO handle short send

	if (ConsumeReceiveWindow(payload.size()) < RECEIVE_WINDOW/ 2)
		SendWindowAdjust(RECEIVE_WINDOW - GetReceiveWindow());
}

void
SocketChannel::OnEof()
{
	socket.GetSocket().ShutdownWrite();
}

void
SocketChannel::OnSocketReady(unsigned events) noexcept
{
	if (events & SocketEvent::ERROR) {
		// TODO log error?
		Close();
		return;
	}

	/* is the kernel's receive buffer empty? */
	bool empty = false;

	if (events & SocketEvent::READ) {
		std::byte buffer[4096];
		std::span<std::byte> dest{buffer};

		if (GetSendWindow() < dest.size()) {
			dest = dest.first(GetSendWindow());
			assert(!dest.empty());
		}

		auto nbytes = socket.GetSocket().ReadNoWait(dest);
		if (nbytes < 0) {
			// TODO log error?
			Close();
			return;
		}

		if (nbytes == 0) {
			Close();
			return;
		}

		SendData(dest.first(nbytes));

		if (GetSendWindow() == 0)
			socket.CancelRead();

		/* the receive buffer is considered empty if the
		   kernel has given us less data than we asked for */
		empty = static_cast<std::size_t>(nbytes) < dest.size();
	}

	if (events & SocketEvent::HANGUP) {
		/* close the socket only if the receive buffer is
		   empty */
		if (empty)
			Close();
	}
}
