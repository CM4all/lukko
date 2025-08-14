// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "SocketChannel.hxx"
#include "Connection.hxx"
#include "ssh/CConnection.hxx"
#include "net/SocketError.hxx"
#include "net/UniqueSocketDescriptor.hxx"

SocketChannel::SocketChannel(SSH::CConnection &_connection,
			     SSH::ChannelInit init,
			     UniqueSocketDescriptor _socket) noexcept
	:SSH::BufferedChannel(_connection, init, RECEIVE_WINDOW),
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

std::size_t
SocketChannel::OnBufferedData(std::span<const std::byte> payload)
{
	const auto nbytes = socket.GetSocket().WriteNoWait(payload);
	if (nbytes < 0) {
		const auto e = GetSocketError();
		if (IsSocketErrorSendWouldBlock(e)) {
			socket.ScheduleWrite();
			return 0;
		}

		throw MakeSocketError(e, "Failed to send");
	}


	const std::size_t consumed = static_cast<std::size_t>(nbytes);
	if (consumed < payload.size())
		socket.ScheduleWrite();

	if (ConsumeReceiveWindow(consumed) < RECEIVE_WINDOW/ 2)
		SendWindowAdjust(RECEIVE_WINDOW - GetReceiveWindow());

	return consumed;
}

void
SocketChannel::OnBufferedEof()
{
	socket.GetSocket().ShutdownWrite();
}

void
SocketChannel::OnWriteBlocked() noexcept
{
	if (GetSendWindow() > 0)
		socket.CancelRead();
}

void
SocketChannel::OnWriteUnblocked() noexcept
{
	if (GetSendWindow() > 0)
		socket.ScheduleRead();
}

void
SocketChannel::OnSocketReady(unsigned events) noexcept
try {
	if (events & SocketEvent::ERROR) {
		// TODO log error?
		Close();
		return;
	}

	if (events & SocketEvent::WRITE) {
		socket.CancelWrite();
		ReadBuffer();
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
} catch (...) {
	GetConnection().CloseError(std::current_exception());
}
