# pcsx2-dbg — PCSX2 with the Orpheus HTTP debugger API

This is a fork of [PCSX2](https://github.com/PCSX2/pcsx2), the free and
open-source PlayStation 2 emulator. The `orpheus-http-api` branch adds
**Orpheus**, a small local HTTP server that exposes PCSX2's debugger core —
registers, memory, execution control, breakpoints, watchpoints, and a
memory-access trace — to external tools as plain JSON over HTTP.

Everything else is unmodified upstream PCSX2; see the
[upstream README](https://github.com/PCSX2/pcsx2#readme) for general
information about the emulator itself.

## Why

PCSX2's built-in debugger is interactive and GUI-bound, and the existing PINE
IPC protocol only covers memory reads/writes and game metadata. Orpheus makes
the *debugger* scriptable: any program that can issue HTTP requests — a Python
script, a Go tool, a Ghidra plugin, an LLM agent — can inspect and steer a
running game without linking against PCSX2 or speaking a binary protocol.

Use cases this was built for:

- **Dynamic analysis / reverse engineering** — resolve what static analysis
  can't: dump registers and memory at interesting points, set breakpoints on
  suspected functions, and confirm hypotheses against the live game.
- **"Catch the accessor"** — you know *where* a value lives (e.g. from a cheat
  table) but not *what code* touches it. Set a trace watchpoint on the address
  and read back the program counter of every instruction that loads or stores
  it, at full emulation speed, without pausing the game.
- **Debugger frontends** — bridge PCSX2 into an external debugger UI.
  [Eurydice](https://github.com/NoTjugotre/Eurydice) does exactly this: a
  Ghidra TraceRMI agent that connects this API to Ghidra's Debugger UI, giving
  you live EE/IOP sessions inside Ghidra.
- **Automation** — regression-test game patches, record execution traces,
  drive the emulator from CI or batch jobs.

The API was designed as the dynamic-analysis backend of
[Orpheus](https://github.com/NoTjugotre/Orpheus), a Go CLI
disassembler/decompiler pipeline for PS2 binaries, but it is deliberately
generic and tool-agnostic.

## The HTTP API

The server starts automatically with the VM and listens on
**`127.0.0.1:28052`** (loopback only, no authentication — it is a local
debugging interface, not a network service). All responses are
`application/json`. Where an endpoint takes a `cpu` parameter, valid values
are `ee` (the R5900 main CPU, default) and `iop` (the R3000A I/O processor).
Numeric parameters accept decimal or `0x`-prefixed hex.

### Inspection

| Endpoint | Description |
| --- | --- |
| `GET /status` | VM state: whether a VM is running, paused flag, current EE and IOP program counters, EE cycle count. |
| `GET /registers?cpu=ee\|iop` | Full register dump, grouped by category (GPR, COP0, FPU, …) as 128-bit hex values. |
| `GET /memory?cpu=ee\|iop&addr=<a>&len=<n>` | Read `n` bytes (default 16, capped at 65536 per request) from the given virtual address; returns a hex string plus an `ok` flag. |

```console
$ curl -s 'http://127.0.0.1:28052/status'
{"vm":true,"paused":false,"ee_pc":"0x00203df8","iop_pc":"0x0000cd50","ee_cycles":1073741824}

$ curl -s 'http://127.0.0.1:28052/memory?cpu=ee&addr=0x00100000&len=16'
{"addr":"0x00100000","len":16,"ok":true,"hex":"7f4f01084d3f0108..."}
```

Reads are performed directly against emulated memory (PINE-style): they are
safe (no crashes or deadlocks) but not synchronized with a running core, so
values from a live game are instantaneous snapshots. Pause first if you need
a consistent view.

### Execution control

| Endpoint | Description |
| --- | --- |
| `POST /pause` | Pause the virtual machine. |
| `POST /resume` | Resume the virtual machine. |

### Breakpoints

| Endpoint | Description |
| --- | --- |
| `GET /breakpoints?cpu=` | List breakpoints: address and enabled flag. |
| `POST /breakpoints?cpu=&addr=<a>` | Add an execution breakpoint. When hit, the VM pauses (observe via `/status`). |
| `DELETE /breakpoints?cpu=&addr=<a>` | Remove a breakpoint. |

### Watchpoints (memchecks)

| Endpoint | Description |
| --- | --- |
| `GET /watchpoints?cpu=` | List watchpoints: range, condition, hit count, and the PC/address/size of the last hit. |
| `POST /watchpoints?cpu=&start=<a>&end=<b>&cond=r\|w\|rw` | Watch the address range `[start, end)` for reads, writes, or both (default `rw`). `end` defaults to `start + 1`. |
| `DELETE /watchpoints?cpu=&start=<a>&end=<b>` | Remove a watchpoint. |

Watchpoints added through this API are **trace watchpoints**: instead of
pausing emulation, every hit records the accessing instruction's PC, the
effective address, and the access direction into an in-memory ring buffer,
and execution continues at full speed. This is the "catch the accessor"
primitive. Current limitation: reliable for **one trace watchpoint at a
time** per CPU (a recompiler register-preservation constraint).

Control and mutation requests (`/pause`, `/resume`, breakpoint/watchpoint
add/remove) are marshalled onto the emulator's CPU thread fire-and-forget:
the HTTP response `{"ok":true}` acknowledges that the request was queued, and
the effect is observable through the read endpoints.

### Memory-access trace

| Endpoint | Description |
| --- | --- |
| `GET /trace` | Drain the ring buffer of recorded accesses. Each record: `cpu`, `pc`, `addr`, `size`, `write`. The buffer is cleared on read. |

The buffer holds up to 200,000 records; on overflow the oldest records are
dropped and the drop count is reported in the response, so a polling client
can tell whether its trace is complete:

```console
$ curl -s 'http://127.0.0.1:28052/trace'
{"dropped":0,"count":3,"accesses":[
  {"cpu":"ee","pc":"0x00203df8","addr":"0x004a55c0","size":0,"write":false},
  ...]}
```

### Typical "catch the accessor" session

```console
$ curl -s -X POST 'http://127.0.0.1:28052/watchpoints?cpu=ee&start=0x004a55c0&cond=w'
{"ok":true}
# ... play the game until the value changes ...
$ curl -s 'http://127.0.0.1:28052/trace'          # PCs of every writer
$ curl -s -X DELETE 'http://127.0.0.1:28052/watchpoints?cpu=ee&start=0x004a55c0'
```

## Implementation notes

- The server lives in [`pcsx2/Orpheus.cpp`](pcsx2/Orpheus.cpp) /
  [`Orpheus.h`](pcsx2/Orpheus.h), runs on its own thread, and mirrors PINE's
  lifecycle (started in `VMManager::Internal::CPUThreadInitialize`, stopped on
  shutdown). The default port is `ORPHEUS_DEFAULT_PORT` (28052), distinct
  from PINE's slot.
- Trace recording hooks the debugger memcheck path: `MemCheck::Log` and the
  EE/IOP recompiler memcheck handlers (`dynarecMemcheck` /
  `psxDynarecMemcheck`) feed `OrpheusServer::RecordMemAccess` and continue
  instead of pausing.
- **Platform support:** POSIX only (Linux/macOS) for now. On Windows the
  server is stubbed out and logs a warning; the rest of the emulator builds
  and runs normally.

## Related projects

- **[Orpheus](https://github.com/NoTjugotre/Orpheus)** — Go CLI
  disassembler/decompiler for PS2 binaries; this API is its dynamic-analysis
  backend.
- **[Eurydice](https://github.com/NoTjugotre/Eurydice)** — Ghidra Debugger
  connector for PCSX2: a TraceRMI agent bridging this HTTP API into Ghidra's
  Debugger UI. A useful reference implementation of a client.
- **[PCSX2](https://github.com/PCSX2/pcsx2)** — the upstream emulator.

## Building and license

Build exactly as upstream PCSX2 — see the
[upstream build documentation](https://github.com/PCSX2/pcsx2/wiki). Like
PCSX2 itself, this fork is licensed under the
[GPL-3.0+](https://github.com/PCSX2/pcsx2/blob/master/COPYING.GPLv3).
