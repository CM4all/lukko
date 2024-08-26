// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "LoginClient.hxx"
#include "translation/Parser.hxx"
#include "translation/Protocol.hxx"
#include "translation/Response.hxx"
#include "AllocatorPtr.hxx"
#include "event/SocketEvent.hxx"
#include "net/SocketError.hxx"
#include "net/UniqueSocketDescriptor.hxx"
#include "co/AwaitableHelper.hxx"
#include "co/Task.hxx"
#include "util/StaticFifoBuffer.hxx"
#include "util/SpanCast.hxx"

#include <stdexcept>

#include <string.h>
#include <sys/socket.h>

static void
Write(std::byte *&p, std::span<const std::byte> src) noexcept
{
	p = std::copy(src.begin(), src.end(), p);
}

template<typename T>
static void
WriteT(std::byte *&p, const T &src) noexcept
{
	Write(p, std::as_bytes(std::span{&src, 1}));
}

static void
WriteHeader(std::byte *&p, TranslationCommand command, size_t size) noexcept
{
	TranslationHeader header;
	header.length = (uint16_t)size;
	header.command = command;

	WriteT(p, header);
}

static void
WritePacket(std::byte *&p, TranslationCommand cmd)
{
	WriteHeader(p, cmd, 0);
}

static void
WritePacket(std::byte *&p, TranslationCommand cmd,
	    std::span<const std::byte> payload)
{
	WriteHeader(p, cmd, payload.size());
	Write(p, payload);
}

static void
WritePacket(std::byte *&p, TranslationCommand cmd,
	    std::string_view payload)
{
	WritePacket(p, cmd, AsBytes(payload));
}

static void
SendFull(SocketDescriptor fd, std::span<const std::byte> buffer)
{
	ssize_t nbytes = fd.Send(buffer);
	if (nbytes < 0)
		throw MakeSocketError("send() to translation server failed");

	if (size_t(nbytes) != buffer.size())
		throw std::runtime_error("Short send() to translation server");
}

static void
SendTranslateLogin(SocketDescriptor fd,
		   std::string_view service, std::string_view listener_tag,
		   std::string_view user, std::string_view password)
{
	assert(user.data() != nullptr);

	if (user.size() > 256)
		throw std::runtime_error("User name too long");

	if (password.size() > 256)
		throw std::runtime_error("Password too long");

	std::byte buffer[1024], *p = buffer;

	WritePacket(p, TranslationCommand::BEGIN);
	WritePacket(p, TranslationCommand::LOGIN);
	WritePacket(p, TranslationCommand::SERVICE, service);

	if (listener_tag.data() != nullptr)
		WritePacket(p, TranslationCommand::LISTENER_TAG, listener_tag);

	WritePacket(p, TranslationCommand::USER, user);

	if (password.data() != nullptr)
		WritePacket(p, TranslationCommand::PASSWORD, password);

	WritePacket(p, TranslationCommand::END);

	const size_t size = (std::byte *)p - buffer;
	SendFull(fd, {buffer, size});
}

class CoSocketEvent final {
	SocketEvent socket;

	std::coroutine_handle<> continuation;

	bool ready = false;

	using Awaitable = Co::AwaitableHelper<CoSocketEvent, false>;
	friend Awaitable;

public:
	CoSocketEvent(EventLoop &event_loop, SocketDescriptor _socket) noexcept
		:socket(event_loop, BIND_THIS_METHOD(OnSocketReady), _socket) {}

	[[nodiscard]]
	Awaitable operator co_await() noexcept {
		ready = false;
		socket.ScheduleRead();
		return *this;
	}

private:
	bool IsReady() const noexcept {
		return ready;
	}

	void TakeValue() const noexcept {}

	void OnSocketReady(unsigned) noexcept {
		if (ready) {
			socket.CancelRead();
			return;
		}

		ready = true;

		if (continuation)
			continuation.resume();
	}
};

static Co::Task<TranslateResponse>
ReceiveResponse(EventLoop &event_loop,
		AllocatorPtr alloc, UniqueSocketDescriptor fd)
{
	TranslateResponse response;
	TranslateParser parser(alloc, response);

	StaticFifoBuffer<std::byte, 8192> buffer;

	CoSocketEvent event{event_loop, fd};
	co_await event;

	while (true) {
		auto w = buffer.Write();
		if (w.empty())
			throw std::runtime_error("Translation receive buffer is full");

		ssize_t nbytes = recv(fd.Get(), w.data(), w.size(), MSG_NOSIGNAL);
		if (nbytes < 0) {
			const auto e = GetSocketError();
			if (IsSocketErrorReceiveWouldBlock(e)) {
				co_await event;
				continue;
			}

			throw MakeSocketError(e, "recv() from translation server failed");
		}

		if (nbytes == 0)
			throw std::runtime_error("Translation server hung up");

		buffer.Append(nbytes);

		while (true) {
			auto r = buffer.Read();
			if (r.empty())
				break;

			size_t consumed = parser.Feed(r);
			if (consumed == 0)
				break;

			buffer.Consume(consumed);

			auto result = parser.Process();
			switch (result) {
			case TranslateParser::Result::MORE:
				break;

			case TranslateParser::Result::DONE:
				if (!buffer.empty())
					throw std::runtime_error("Excessive data from translation server");

				co_return response;
			}
		}
	}
}

Co::Task<TranslateResponse>
TranslateLogin(EventLoop &event_loop,
	       AllocatorPtr alloc, UniqueSocketDescriptor fd,
	       std::string_view service, std::string_view listener_tag,
	       std::string_view user, std::string_view password)
{
	SendTranslateLogin(fd, service, listener_tag, user, password);
	return ReceiveResponse(event_loop, alloc, std::move(fd));
}
