// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "Channel.hxx"
#include "CConnection.hxx"
#include "Serializer.hxx"
#include "MakePacket.hxx"

using std::string_view_literals::operator""sv;

namespace SSH {

Channel::Channel(CConnection &_connection, ChannelInit init,
		 std::size_t _receive_window) noexcept
	:connection(_connection),
	 local_channel(init.local_channel),
	 peer_channel(init.peer_channel),
	 receive_window(_receive_window),
	 send_window(init.send_window) {}

Channel::~Channel() noexcept = default;

void
Channel::Close()
{
	connection.CloseChannel(*this);
}

std::size_t
Channel::ConsumeReceiveWindow(std::size_t nbytes) noexcept
{
	assert(nbytes <= receive_window);

	return receive_window -= nbytes;
}

void
Channel::SendWindowAdjust(uint_least32_t nbytes)
{
	assert(nbytes > 0);
	assert(nbytes <= SIZE_MAX - receive_window);

	connection.SendPacket(MakeChannelWindowAdjust(GetPeerChannel(), nbytes));

	receive_window += nbytes;
}

void
Channel::SendData(std::span<const std::byte> src)
{
	assert(src.size() <= send_window);

	PacketSerializer s{MessageNumber::CHANNEL_DATA};
	s.WriteU32(GetPeerChannel());
	s.WriteLengthEncoded(src);
	connection.SendPacket(std::move(s));

	send_window -= src.size();
}

void
Channel::SendExtendedData(ChannelExtendedDataType data_type,
			  std::span<const std::byte> src)
{
	assert(src.size() <= send_window);

	PacketSerializer s{MessageNumber::CHANNEL_EXTENDED_DATA};
	s.WriteU32(GetPeerChannel());
	s.WriteU32(static_cast<uint_least32_t>(data_type));
	s.WriteLengthEncoded(src);
	connection.SendPacket(std::move(s));

	send_window -= src.size();
}

void
Channel::SendStderr(std::span<const std::byte> src)
{
	SendExtendedData(ChannelExtendedDataType::STDERR, src);
}

void
Channel::SendEof()
{
	PacketSerializer s{MessageNumber::CHANNEL_EOF};
	s.WriteU32(GetPeerChannel());
	connection.SendPacket(std::move(s));
}

void
Channel::SendExitStatus(uint_least32_t exit_status)
{
	auto s = MakeChannelReqest(GetPeerChannel(), "exit-status"sv, false);
	s.WriteU32(exit_status);
	connection.SendPacket(std::move(s));
}

void
Channel::SendExitSignal(std::string_view signal_name, bool core_dumped,
			std::string_view error_message)
{
	auto s = MakeChannelReqest(GetPeerChannel(), "exit-signal"sv, false);
	s.WriteString(signal_name);
	s.WriteBool(core_dumped);
	s.WriteString(error_message);
	s.WriteString("en"sv);
	connection.SendPacket(std::move(s));
}

void
Channel::SerializeOpenConfirmation([[maybe_unused]] Serializer &s) const
{
}

void
Channel::HandleRequest(std::string_view request_type,
		       std::span<const std::byte> type_specific,
		       bool want_reply)
{
	const bool success = OnRequest(request_type, type_specific);

	if (want_reply) {
		PacketSerializer s{
			success
			? MessageNumber::CHANNEL_SUCCESS
			: MessageNumber::CHANNEL_FAILURE,
		};

		s.WriteU32(peer_channel);
		connection.SendPacket(std::move(s));
	}
}

void
Channel::OnWindowAdjust(std::size_t nbytes)
{
	send_window += nbytes;
}

void
Channel::OnData([[maybe_unused]] std::span<const std::byte> payload)
{
	ConsumeReceiveWindow(payload.size());
}

void
Channel::OnExtendedData([[maybe_unused]] ChannelExtendedDataType data_type,
			[[maybe_unused]] std::span<const std::byte> payload)
{
	ConsumeReceiveWindow(payload.size());
}

bool
Channel::OnRequest([[maybe_unused]] std::string_view request_type,
		   [[maybe_unused]] std::span<const std::byte> type_specific)
{
	return false;
}

} // namespace SSH
