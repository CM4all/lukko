// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <max.kellermann@ionos.com>

#pragma once

#include "util/AllocatedArray.hxx"

#include <cstddef>
#include <list>

using BufferList = std::list<AllocatedArray<std::byte>>;
