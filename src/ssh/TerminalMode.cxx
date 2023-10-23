// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "TerminalMode.hxx"
#include "util/ByteOrder.hxx"

#include <cstdint>

#include <termios.h>

namespace SSH {

enum class TerminalModeOpcode : uint8_t {
	END = 0,
	VINTR_ = 1,
	VQUIT_ = 2,
	VERASE_ = 3,
	VKILL_ = 4,
	VEOF_ = 5,
	VEOL_ = 6,
	VEOL2_ = 7,
	VSTART_ = 8,
	VSTOP_ = 9,
	VSUSP_ = 10,
	VDSUSP_ = 11,
	VREPRINT_ = 12,
	VWERASE_ = 13,
	VLNEXT_ = 14,
	VFLUSH_ = 15,
	VSWTCH_ = 16,
	VSTATUS_ = 17,
	VDISCARD_ = 18,
	IGNPAR_ = 30,
	PARMRK_ = 31,
	INPCK_ = 32,
	ISTRIP_ = 33,
	INLCR_ = 34,
	IGNCR_ = 35,
	ICRNL_ = 36,
	IUCLC_ = 37,
	IXON_ = 38,
	IXANY_ = 39,
	IXOFF_ = 40,
	IMAXBEL_ = 41,
	ISIG_ = 50,
	ICANON_ = 51,
	XCASE_ = 52,
	ECHO_ = 53,
	ECHOE_ = 54,
	ECHOK_ = 55,
	ECHONL_ = 56,
	NOFLSH_ = 57,
	TOSTOP_ = 58,
	IEXTEN_ = 59,
	ECHOCTL_ = 60,
	ECHOKE_ = 61,
	PENDIN_ = 62,
	OPOST_ = 70,
	OLCUC_ = 71,
	ONLCR_ = 72,
	OCRNL_ = 73,
	ONOCR_ = 74,
	ONLRET_ = 75,
	CS7_ = 90,
	CS8_ = 91,
	PARENB_ = 92,
	PARODD_ = 93,
	ISPEED_ = 128,
	OSPEED_ = 129,
};

static constexpr speed_t
BaudToSpeed(int baud) noexcept
{
	switch (baud) {
	case 0:
		return B0;
	case 50:
		return B50;
	case 75:
		return B75;
	case 110:
		return B110;
	case 134:
		return B134;
	case 150:
		return B150;
	case 200:
		return B200;
	case 300:
		return B300;
	case 600:
		return B600;
	case 1200:
		return B1200;
	case 1800:
		return B1800;
	case 2400:
		return B2400;
	case 4800:
		return B4800;
	case 9600:
		return B9600;
	case 19200:
		return B19200;
	case 38400:
		return B38400;
	case 57600:
		return B57600;
	case 115200:
		return B115200;
	case 230400:
		return B230400;
	default:
		return B9600;
	}
}

template<typename T>
static void
ApplyBit(T &dest, unsigned bit, bool on) noexcept
{
	if (on)
		dest |= bit;
	else
		dest &= ~bit;
}

void
ParseTerminalModes(struct termios &tio, std::span<const std::byte> src) noexcept
{
	while (src.size() >= 5) {
		const auto opcode = static_cast<SSH::TerminalModeOpcode>(src.front());
		if (opcode == SSH::TerminalModeOpcode::END ||
		    static_cast<unsigned>(opcode) >= 160)
			break;

		const uint_least32_t arg = *(const PackedBE32 *)(src.data() + 1);
		src = src.subspan(5);

		switch (opcode) {
		case SSH::TerminalModeOpcode::END:
			// alreadyy handled above
			break;

		case SSH::TerminalModeOpcode::VINTR_:
			tio.c_cc[VINTR] = arg;
			break;

		case SSH::TerminalModeOpcode::VQUIT_:
			tio.c_cc[VQUIT] = arg;
			break;

		case SSH::TerminalModeOpcode::VERASE_:
			tio.c_cc[VERASE] = arg;
			break;

		case SSH::TerminalModeOpcode::VKILL_:
			tio.c_cc[VKILL] = arg;
			break;

		case SSH::TerminalModeOpcode::VEOF_:
			tio.c_cc[VEOF] = arg;
			break;

		case SSH::TerminalModeOpcode::VEOL_:
			tio.c_cc[VEOL] = arg;
			break;

		case SSH::TerminalModeOpcode::VEOL2_:
			tio.c_cc[VEOL2] = arg;
			break;

		case SSH::TerminalModeOpcode::VSTART_:
			tio.c_cc[VSTART] = arg;
			break;

		case SSH::TerminalModeOpcode::VSTOP_:
			tio.c_cc[VSTOP] = arg;
			break;

		case SSH::TerminalModeOpcode::VSUSP_:
			tio.c_cc[VSUSP] = arg;
			break;

		case SSH::TerminalModeOpcode::VDSUSP_:
#ifdef VDSUSP
			tio.c_cc[VDSUSP] = arg;
#endif
			break;

		case SSH::TerminalModeOpcode::VREPRINT_:
			tio.c_cc[VREPRINT] = arg;
			break;

		case SSH::TerminalModeOpcode::VWERASE_:
			tio.c_cc[VWERASE] = arg;
			break;

		case SSH::TerminalModeOpcode::VLNEXT_:
			tio.c_cc[VLNEXT] = arg;
			break;

		case SSH::TerminalModeOpcode::VFLUSH_:
#ifdef VFLUSH
			tio.c_cc[VFLUSH] = arg;
#endif
			break;

		case SSH::TerminalModeOpcode::VSWTCH_:
#ifdef VSWTCH
			tio.c_cc[VSWTCH] = arg;
#endif
			break;

		case SSH::TerminalModeOpcode::VSTATUS_:
#ifdef VSTATUS
			tio.c_cc[VSTATUS] = arg;
#endif
			break;

		case SSH::TerminalModeOpcode::VDISCARD_:
			tio.c_cc[VDISCARD] = arg;
			break;

		case SSH::TerminalModeOpcode::IGNPAR_:
			ApplyBit(tio.c_iflag, IGNPAR, arg);
			break;

		case SSH::TerminalModeOpcode::PARMRK_:
			ApplyBit(tio.c_iflag, PARMRK, arg);
			break;

		case SSH::TerminalModeOpcode::INPCK_:
			ApplyBit(tio.c_iflag, INPCK, arg);
			break;

		case SSH::TerminalModeOpcode::ISTRIP_:
			ApplyBit(tio.c_iflag, ISTRIP, arg);
			break;

		case SSH::TerminalModeOpcode::INLCR_:
			ApplyBit(tio.c_iflag, INLCR, arg);
			break;

		case SSH::TerminalModeOpcode::IGNCR_:
			ApplyBit(tio.c_iflag, IGNCR, arg);
			break;

		case SSH::TerminalModeOpcode::ICRNL_:
			ApplyBit(tio.c_iflag, ICRNL, arg);
			break;

		case SSH::TerminalModeOpcode::IUCLC_:
			ApplyBit(tio.c_iflag, IUCLC, arg);
			break;

		case SSH::TerminalModeOpcode::IXON_:
			ApplyBit(tio.c_iflag, IXON, arg);
			break;

		case SSH::TerminalModeOpcode::IXANY_:
			ApplyBit(tio.c_iflag, IXANY, arg);
			break;

		case SSH::TerminalModeOpcode::IXOFF_:
			ApplyBit(tio.c_iflag, IXOFF, arg);
			break;

		case SSH::TerminalModeOpcode::IMAXBEL_:
			ApplyBit(tio.c_iflag, IMAXBEL, arg);
			break;

		case SSH::TerminalModeOpcode::ISIG_:
			ApplyBit(tio.c_lflag, ISIG, arg);
			break;

		case SSH::TerminalModeOpcode::ICANON_:
			ApplyBit(tio.c_lflag, ICANON, arg);
			break;

		case SSH::TerminalModeOpcode::XCASE_:
			ApplyBit(tio.c_lflag, XCASE, arg);
			break;

		case SSH::TerminalModeOpcode::ECHO_:
			ApplyBit(tio.c_lflag, ECHO, arg);
			break;

		case SSH::TerminalModeOpcode::ECHOE_:
			ApplyBit(tio.c_lflag, ECHOE, arg);
			break;

		case SSH::TerminalModeOpcode::ECHOK_:
			ApplyBit(tio.c_lflag, ECHOK, arg);
			break;

		case SSH::TerminalModeOpcode::ECHONL_:
			ApplyBit(tio.c_lflag, ECHONL, arg);
			break;

		case SSH::TerminalModeOpcode::NOFLSH_:
			ApplyBit(tio.c_lflag, NOFLSH, arg);
			break;

		case SSH::TerminalModeOpcode::TOSTOP_:
			ApplyBit(tio.c_lflag, TOSTOP, arg);
			break;

		case SSH::TerminalModeOpcode::IEXTEN_:
			ApplyBit(tio.c_lflag, IEXTEN, arg);
			break;

		case SSH::TerminalModeOpcode::ECHOCTL_:
			ApplyBit(tio.c_lflag, ECHOCTL, arg);
			break;

		case SSH::TerminalModeOpcode::ECHOKE_:
			ApplyBit(tio.c_lflag, ECHOKE, arg);
			break;

		case SSH::TerminalModeOpcode::PENDIN_:
			ApplyBit(tio.c_lflag, PENDIN, arg);
			break;

		case SSH::TerminalModeOpcode::OPOST_:
			ApplyBit(tio.c_oflag, OPOST, arg);
			break;

		case SSH::TerminalModeOpcode::OLCUC_:
			ApplyBit(tio.c_oflag, OLCUC, arg);
			break;

		case SSH::TerminalModeOpcode::ONLCR_:
			ApplyBit(tio.c_oflag, ONLCR, arg);
			break;

		case SSH::TerminalModeOpcode::OCRNL_:
			ApplyBit(tio.c_oflag, OCRNL, arg);
			break;

		case SSH::TerminalModeOpcode::ONOCR_:
			ApplyBit(tio.c_oflag, ONOCR, arg);
			break;

		case SSH::TerminalModeOpcode::ONLRET_:
			ApplyBit(tio.c_oflag, ONLRET, arg);
			break;

		case SSH::TerminalModeOpcode::CS7_:
			ApplyBit(tio.c_cflag, CS7, arg);
			break;

		case SSH::TerminalModeOpcode::CS8_:
			ApplyBit(tio.c_cflag, CS8, arg);
			break;

		case SSH::TerminalModeOpcode::PARENB_:
			ApplyBit(tio.c_cflag, PARENB, arg);
			break;

		case SSH::TerminalModeOpcode::PARODD_:
			ApplyBit(tio.c_cflag, PARODD, arg);
			break;

		case SSH::TerminalModeOpcode::ISPEED_:
			cfsetispeed(&tio, BaudToSpeed(arg));
			break;

		case SSH::TerminalModeOpcode::OSPEED_:
			cfsetospeed(&tio, BaudToSpeed(arg));
			break;
		}
	}
}

} // namespace SSH
