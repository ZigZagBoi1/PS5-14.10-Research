# Debug Settings Dependency Graph -- PS5 14.10

> Analysis of what controls Debug Settings visibility on retail PS5 and the
> minimum primitives needed to enable it.

## What Debug Settings Is

Debug Settings is a developer/QA menu built into every PS5 firmware. On devkits
and testkits it is visible by default. On retail consoles it is hidden behind a
runtime check. When enabled, it exposes options for package installation, network
diagnostics, display testing, and other development functions.

## How Previous Firmwares Enabled It

### Firmware 1.xx-4.xx (TheFloW, 2021)

TheFloW demonstrated Debug Settings on retail PS5 FW 4.03 in November 2021. The
method was never publicly released, but the community established:

- A **kernel exploit** was required (not just userland)
- The enable mechanism involved **patching a flag in kernel memory** at runtime
- Even when enabled, many options errored out on retail (CE-109543-2)

### Firmware 4.03-4.51 (Public Jailbreak, 2022)

The public 4.03/4.50/4.51 jailbreak (based on the ipv6 UAF) enabled Debug
Settings by:

1. Achieving kernel read/write via the ipv6 use-after-free
2. Patching `security_flags` in the kernel's credential structure
3. Writing the debug settings permission flag in the registry manager's memory

The specific mechanism: `sceRegMgrSetInt` (or its kernel equivalent) sets a
registry key that the Settings app checks. The key path is believed to be in
the `system_prof_settings` domain. With kernel R/W, the attacker either:
- Calls the registry setter directly from kernel context, or
- Patches the process credential to bypass the privilege check, then calls it
  from userland

### Firmware 13.60 (Relapse Exploit, 2026)

The Relapse chain (ntfargo) on 13.60 used:
1. WebKit Symbol.prototype.toString heap byte leak
2. Structured clone corruption for arbitrary R/W in WebProcess
3. Scope object leak for code execution
4. Kernel exploit via ipv6 UAF (IPV6_2292PKTOPTIONS)
5. Debug Settings enabled via kernel write to registry flag

**All three Relapse primitives are DEAD on 14.10** (p642). The ipv6 option is
also blocked.

### Firmware 14.10 (Gezine, October 2026)

Gezine demonstrated Debug Settings on 14.10 in a video titled "Hello 14.10"
(October 19, 2026). Key facts from the [worldcybernews report](https://www.worldcybernews.com/articles/1612):

- The technique is "unrelated to the earlier Relapse exploit chain"
- Technical details were NOT disclosed
- It "does not grant full control of the console"
- Game executable extraction no longer works on 14.xx
- Hypervisor bypass would be needed for full extraction

This confirms Debug Settings IS reachable on 14.10 with a new technique, but
the primitive set is unknown.

## Dependency Graph

```
Debug Settings visible in UI
          |
          v
Registry flag set (sceRegMgrSetInt or kernel equivalent)
          |
          v
Kernel write primitive (to patch flag or bypass credential check)
          |
          v
Kernel read primitive (to find flag location via KASLR-adjusted offset)
          |
          v
Kernel vulnerability exploitation (UAF, overflow, type confusion)
          |
          v
WebProcess arbitrary R/W (to build kernel exploit payload)
          |
          v
WebProcess info leak (to defeat ASLR and find code/heap addresses)
          |
          v
WebKit memory corruption (Canvas UAF, FontFace UAF -- HAVE THIS)
          |
          v
Browser entry from game process (guide redirect -- HAVE THIS)
          |
          v
Userland code execution (Lua TCP loader -- HAVE THIS)
```

## What We Have vs What We Need

| Dependency | Status | Evidence |
|------------|--------|----------|
| Userland code exec | DONE | Lua loader on TCP 9026 |
| Browser entry | DONE | Guide redirect demonstrated |
| WebKit memory corruption | DONE | FontFace UAF (100% reclaim), Canvas2D UAF |
| Kernel image base | DONE | Fault-code oracle per boot |
| **WebProcess info leak** | **BLOCKED** | No known route -- 25+ CVEs tested, all dead |
| WebProcess arbitrary R/W | BLOCKED | Needs info leak |
| Kernel vulnerability | BLOCKED | Needs WebProcess R/W to exploit |
| Kernel read | BLOCKED | Needs kernel vuln |
| Kernel write | BLOCKED | Needs kernel read |
| Registry flag patch | BLOCKED | Needs kernel write |
| Debug Settings | BLOCKED | Needs registry patch |

## The Single Blocker: WebProcess Text Base

Every step from "WebProcess info leak" onward is a known technique with
published implementations on PS5 (older firmwares). The ONLY missing piece that
prevents the entire chain from working is:

**We cannot determine the WebProcess text base address on 14.10.**

Without this address:
- We cannot resolve gadget addresses for ROP chains
- We cannot forge vtable pointers (the FontFace forge needs valid function ptrs)
- We cannot build the kernel exploit payload

### Why It Is Hard

1. **W^X enforced** -- no JIT code pages, no shellcode
2. **Error.stack** shows url:line:col only, no native addresses
3. **All DFG type confusion CVEs tested** -- patched (p604-p671)
4. **Canvas2D UAF** is a control primitive, not an info leak
5. **dynlib_get_info(593)** returns loader process bases, not WebProcess
6. **CE-108262-9 error codes** carry zero fault-type information
7. **Gigacage active** -- butterfly isolation prevents type confusion
8. **bmalloc iso-heap** -- cross-type reclaim blocked

### Top Candidates (2026-11-09)

1. **CVE-2023-42916** (DFG JIT OOB read) -- fixed Safari 17.1.2, PS5 has 17.0.
   Red Hat confirms it "exposes addresses that help bypass ASLR." Used in
   targeted attacks alongside CVE-2023-42917 as the info-leak stage. DFG JIT is
   active on PS5 (p602). **TOP PRIORITY.**

2. **StructureID prediction** -- if PS5 lacks StructureID randomization (present
   in newer WebKit), a fakeobj primitive becomes possible without needing addrof.
   This is a CVE-independent technique.

3. **JIT CodeBlock pointer leak** -- DFG compilation creates CodeBlock objects on
   the heap. If a GC-related race can expose a CodeBlock pointer, the text base
   can be derived from it.

4. **Community contribution** -- a decrypted 14.00/14.10 WebProcess binary would
   immediately resolve the offset table and unblock the entire chain.

## Minimum Path to Debug Settings

Assuming CVE-2023-42916 provides the info leak:

1. Trigger DFG OOB read to leak WebProcess text base (1 probe)
2. Use FontFace UAF forge with known gadget addresses (existing code)
3. Build arbitrary R/W in WebProcess via forged vtable dispatch
4. Pivot to kernel: use WebProcess sandbox escape or direct syscall
5. Read kernel memory at KASLR-adjusted offset for registry flag location
6. Write registry flag to enable Debug Settings
7. Navigate to Settings -> Debug Settings is now visible

**Estimated probe count to Debug Settings:** 3-5 new probes IF CVE-2023-42916
works. The chain infrastructure (FontFace forge, Canvas UAF, thread ROP) is
already built.

## Is a Full Jailbreak Necessary?

**No.** Debug Settings specifically requires only:
- Kernel read (to find the flag)
- Kernel write (to set the flag)

It does NOT require:
- Hypervisor bypass
- Full sandbox escape
- Persistent modification
- Boot chain compromise

The flag is a runtime patch -- it persists only until reboot. This is consistent
with Gezine's statement that the technique "does not grant full control."

## Registry Key Research

The PS5 registry manager (`sceRegMgr`) stores configuration in a key-value
system. Based on PS4 research and 13.60 analysis:

- Debug Settings permission is likely at a key like
  `system_prof_settings.debug_settings_permission` or
  `/system/common/debug/settings_visible`
- The value is an integer (0 = hidden, 1 = visible)
- The kernel-side setter validates caller credentials
- With kernel write, we can either:
  - Patch the credential check to always pass
  - Write the flag value directly in the registry's memory-mapped storage
  - Patch `security_flags` in the process credential structure

The exact offset on 14.10 requires either:
- A decrypted kernel image (to find the sceRegMgr handler)
- The SDK v0.45 offset (if it includes the registry base)
- A kernel read primitive to search for the flag at runtime

## References

- [PS5 Developer Wiki -- Debug Settings](https://www.psdevwiki.com/ps5/%E2%98%85_Debug_Settings) (403 at time of fetch)
- [Gezine "Hello 14.10" demonstration](https://www.worldcybernews.com/articles/1612) (October 2026)
- [TheFloW Debug Settings on 4.03](https://wololo.net/2021/11/08/ps5-kernel-exploit-theflow-showcases-debug-settings-menu-on-retail-console-no-plan-to-release/) (November 2021)
- SDK v0.45 published offsets: allproc, security_flags, rootvnode
- `docs/EXPLOITATION_STATUS.md` -- current chain status
- `docs/STRATEGY.md` -- full exploit strategy
