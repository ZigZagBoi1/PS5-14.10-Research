# PS5 Research Live-Link App

A homebrew app that runs on a jailbroken PS5 and maintains a persistent
TCP connection back to the research server, allowing live data extraction
and command execution for kernel security research.

## Architecture

```
PS5 (10.0.0.96)                    Server (10.0.0.80)
+------------------+               +------------------+
| research-app.elf |  <-- TCP -->  | server.py        |
| - syscall proxy  |   port 9100  | - command sender  |
| - memory dumper  |               | - data receiver   |
| - file browser   |               | - auto-reconnect  |
| - proc info      |               | - web dashboard   |
+------------------+               +------------------+
```

## What It Can Do

Once the PS5 is jailbroken and this app is running:

- **Memory dumps**: Read arbitrary process memory regions
- **Syscall proxy**: Execute syscalls with arbitrary arguments
- **File browser**: List and read files from the PS5 filesystem
- **Process info**: PID, memory maps, loaded modules
- **Kernel info**: sysctl tree, device nodes, mount points
- **Live shell**: Interactive command execution
- **Auto-reconnect**: Reconnects whenever the PS5 is on the network

## Building

The ELF needs to be compiled for PS5 (FreeBSD x86_64, Sony toolchain).
This requires the PS5 SDK or a cross-compilation setup targeting
FreeBSD/amd64 with the PS5 ABI.

For now, the research probes sent via the Lua loader (port 9026) serve
the same purpose. This app would make it persistent and automatic.

## Protocol

Simple JSON-over-TCP with length prefix:

```
[4 bytes: message length (LE)] [JSON payload]

Commands (server -> PS5):
  {"cmd": "sysctl", "mib": [1, 14, 1, <pid>]}
  {"cmd": "read_mem", "addr": "0x...", "size": 4096}
  {"cmd": "syscall", "num": 202, "args": [...]}
  {"cmd": "ls", "path": "/dev"}
  {"cmd": "read_file", "path": "/app0/eboot.bin", "offset": 0, "size": 4096}
  {"cmd": "info"}
  {"cmd": "ping"}

Responses (PS5 -> server):
  {"status": "ok", "data": {...}}
  {"status": "error", "message": "..."}
  {"status": "pong", "uptime": 123}
```
