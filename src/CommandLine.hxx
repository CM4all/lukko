// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

struct CommandLine {
	const char *config_path = "/etc/cm4all/lukko/lukko.conf";
};

CommandLine
ParseCommandLine(int argc, char **argv);
