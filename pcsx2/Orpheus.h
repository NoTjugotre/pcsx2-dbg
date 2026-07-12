// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

// Orpheus HTTP API — a small HTTP server exposing PCSX2's debugger core
// (registers, memory, breakpoints, watchpoints, execution control) to external
// tooling for dynamic analysis. Companion to PINE (which only covers memory +
// metadata). See docs: Orpheus project, "PCSX2 Debugger Interface" reference.

#pragma once

// Local-only TCP port. Distinct from PINE's default slot (28011).
#define ORPHEUS_DEFAULT_PORT 28052

namespace OrpheusServer
{
	bool IsInitialized();
	int GetPort();

	bool Initialize(int port = ORPHEUS_DEFAULT_PORT);
	void Deinitialize();
} // namespace OrpheusServer
