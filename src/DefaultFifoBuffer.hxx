// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include "memory/SliceFifoBuffer.hxx"

/**
 * A frontend for #SliceFifoBuffer which allows to replace it with a
 * simple heap-allocated buffer when some client code gets copied to
 * another project.
 */
class DefaultFifoBuffer : public SliceFifoBuffer {
public:
	void Allocate() noexcept;
	void AllocateIfNull() noexcept;
	void CycleIfEmpty() noexcept;
};
