// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#include "LoadFile.hxx"
#include "Parser.hxx"
#include "Key.hxx"
#include "system/Error.hxx"
#include "io/FileDescriptor.hxx"
#include "util/ScopeExit.hxx"

#include <sodium/utils.h>

#include <array>

#include <sys/stat.h>

std::unique_ptr<SecretKey>
LoadKeyFile(FileDescriptor fd)
{
	struct stat st;
	if (fstat(fd.Get(), &st) < 0)
		throw MakeErrno("Failed to stat file");

	if (!S_ISREG(st.st_mode))
		throw std::runtime_error{"Not a regular file"};

	std::array<std::byte, 32768> buffer;

	if (st.st_size > (off_t)buffer.size())
		throw std::runtime_error{"File is too large"};

	AtScopeExit(&buffer) { sodium_memzero(&buffer, sizeof(buffer)); };

	const auto nbytes = fd.Read(buffer);
	if (nbytes < 0)
		throw MakeErrno("Failed to read file");

	return ParseSecretKey(std::span{buffer}.first(nbytes));
}
