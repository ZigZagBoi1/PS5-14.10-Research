# WebKit-to-Kernel Path Analysis 5: Jail/Sandbox Escape and Module Loading

## Source Material
- Kernel: sys 629 (jail bypass), sys 630 (mount companion), sys 593/608/660 (dynlib_get_info_ex ASLR bypass), sys 612/649 (module member leak), sys 675 (global state reset), sys 532 (SceRegMgr)
- WebKit: WebKit-1200 source (PS5 port), PlayStation platform layer, process launcher, cmake build config

---

## FINDING 1: PS5 Browser Process Sandboxing is MINIMAL — No FreeBSD Jail, No Capsicum, No seccomp

### Evidence from WebKit Source

**AuxiliaryProcess::initializeSandbox() is a NO-OP on PlayStation.**

In `Source/WebKit/Shared/AuxiliaryProcess.cpp` line 235:
```cpp
void AuxiliaryProcess::initializeSandbox(const AuxiliaryProcessInitializationParameters&, SandboxInitializationParameters&)
{
}
```
This is the `#if !PLATFORM(COCOA)` fallback. The PlayStation platform provides NO override — there is no `AuxiliaryProcessPlayStation.cpp` that overrides this. GPUProcessPlayStation.cpp confirms:
```cpp
void GPUProcess::initializeSandbox(const AuxiliaryProcessInitializationParameters&, SandboxInitializationParameters&)
{
}
```
Empty body. No sandbox initialization whatsoever.

**No jail, capsicum, pledge, seccomp, or sandbox_init references exist** in any PlayStation-specific WebKit code. Comprehensive grep across the entire Source tree found:
- Zero `jail` references in PlayStation code
- Zero `capsicum` / `cap_enter` references
- Zero `pledge` / `unveil` references  
- Zero `seccomp` / `prctl` references
- Zero `sandbox_init` references
- The only sandbox files are macOS-specific `.sb` Seatbelt profiles

**Conclusion: The PS5 WebKit process almost certainly does NOT run inside a FreeBSD jail.** The kernel jail mechanism (sys 629) is a process-level attribute checked at `td->0x140`, and the WebKit source shows zero code that would set this. The browser is sandboxed only by Sony's proprietary process permission system (authId/capabilities in ucred extensions), NOT by a FreeBSD jail.

### Implication for sys 629
Since the browser process is likely NOT jailed, sys 629 arg0=1 (jail bypass) may not be needed for the browser process itself. HOWEVER:
- If Sony places the browser in a jail at the OS level (outside WebKit's control, via the process launcher binary at `/app0/WebProcess.self`), then sys 629 becomes critical
- The `process-launcher.h` and `nk-webprocess.h` headers are NOT in the WebKit source (they're in the proprietary SDK), so we cannot rule out OS-level jailing
- The process launcher uses `PlayStation::launchProcess()` which is a proprietary API — it MAY set jail attributes

### What IS the sandbox?
Sony uses a **proprietary permission model** instead of FreeBSD jail:
1. **ucred extensions** at process `+0x58` (cr_sceAuthId) and `+0x60/+0x68` (cr_sceCaps)
2. **priv_check with Sony privilege codes** (e.g., 0x2AA = 682 for sys 532)
3. **authId hierarchy** checks (>= 0x3000000, >= 0x5000000 for privileged operations)
4. **Per-syscall whitelisting** — each Sony syscall has its own gates

This means: after WebKit code execution, you can call ANY syscall directly. There is no seccomp filter or system call filter preventing it. The only barrier is per-syscall privilege checks, which many syscalls LACK.

---

## FINDING 2: Browser Process Loads 15+ Sony .sprx Modules via dlopen() — ASLR Bypass is FREE

### Evidence from WebKit Source

**WebProcessMain.cpp** (EntryPoint/playstation/WebProcessMain.cpp) shows the WebProcess loads modules at startup:

```cpp
#include <dlfcn.h>

static void loadLibraryOrExit(const char* name)
{
    if (!dlopen(name, RTLD_NOW)) { ... exit(EXIT_FAILURE); }
}

int main(int argc, char** argv) {
    loadLibraryOrExit(ICU_LOAD_AT);         // libicu.sprx
    loadLibraryOrExit(PNG_LOAD_AT);         // libpng16.sprx
    loadLibraryOrExit(JPEG_LOAD_AT);        // libjpeg.sprx (optional)
    loadLibraryOrExit(WebP_LOAD_AT);        // libwebp.sprx (optional)
    loadLibraryOrExit(Brotli_LOAD_AT);      // libbrotli.sprx (optional)
    loadLibraryOrExit(Freetype_LOAD_AT);    // libfreetype.sprx
    loadLibraryOrExit(Fontconfig_LOAD_AT);  // libfontconfig.sprx
    loadLibraryOrExit(HarfBuzz_LOAD_AT);    // libharfbuzz.sprx
    loadLibraryOrExit(Cairo_LOAD_AT);       // libcairo.sprx
    loadLibraryOrExit(LibPSL_LOAD_AT);      // libpsl.sprx (optional)
    loadLibraryOrExit(LibXml2_LOAD_AT);     // libxml2.sprx (optional)
    loadLibraryOrExit(WebKitRequirements_LOAD_AT);  // libSceNKWebKitRequirements.sprx
    loadLibraryOrExit(WPE_LOAD_AT);         // libwpe.sprx (optional)
    loadLibraryOrExit("libJavaScriptCore"); // libJavaScriptCore.sprx
    loadLibraryOrExit("libWebKit");         // libWebKit.sprx
}
```

The cmake confirms these are shipped as `.sprx` files:
```cmake
set(PLAYSTATION_WebProcess_REQUIRED_SHARED_LIBRARIES
    ${GL_SHARED_LIBRARY_NAME}
    libSceNKWebKitRequirements
    libcairo libfontconfig libfreetype libharfbuzz libicu libpng16
)
# And: file(GLOB INSTALL_WEBKITLIBRARIES_PRX "${WEBKIT_LIBRARIES_DIR}/bin/*.prx")
```

Library names prefixed with `Sce` (e.g., `SceVshBrotli`, `SceVshHarfbuzz`, `SceCairoForWebKit`) confirm these are **Sony system modules** loaded as PRX/SPRX files.

### Connection to sys 593 dynlib_get_info_ex

Each `dlopen()` call maps to a `sceKernelLoadStartModule()` Sony syscall, which creates an entry in the kernel's module list with a unique handle. After WebKit code execution:

1. **Enumerate all module handles** using the dynlib syscalls (sys 591 or similar)
2. **Call sys 593 (dynlib_get_info_ex)** for each handle
3. **Extract mapbase, text_size, data_base_off** from the 0x1a8-byte response — these are copied UNCONDITIONALLY (no priv_check between offsets 0x7f4-0x883)
4. **ASLR is completely defeated** for ALL loaded modules

The WebProcess alone loads 15+ modules. Combined with system libraries (libc, kernel, etc.), this gives complete knowledge of the address space.

### Connection to sys 612/649 module member leak
As a backup/alternative: sys 612/649 `get_obj_member` has ZERO priv_check calls and returns mapbase (0x78), init_proc (0xf8), fini_proc (0x108) via a jump table. This provides targeted per-module extraction.

---

## FINDING 3: No System Call Filter — Direct Syscall Access After Code Execution

### Evidence

1. **No seccomp/capsicum/pledge** in PlayStation WebKit code (confirmed by grep)
2. **Linker wrapping is application-level only**: The cmake wraps `mmap`, `dlopen`, `access`, `lstat`, `getcwd`, `link`, `symlink`, `statvfs` — these are LINKER-LEVEL wraps (`--wrap=mmap`), meaning they intercept calls from WebKit C/C++ code to libc. They do NOT prevent direct syscall invocation.
3. **`memory_extra::vss::*` replaces standard mmap** — Sony's custom memory allocator. But this is a library-level abstraction, not a kernel-level filter.
4. **JIT is DISABLED** (`ENABLE_JIT OFF`, `ENABLE_FTL_JIT OFF`, `ENABLE_DFG_JIT OFF`) — this means JSC uses interpreter-only mode. After a memory corruption exploit, the attacker writes shellcode to RWX memory obtained via sys 588 or similar.

### Post-exploitation syscall access
After gaining code execution in the WebProcess (e.g., via the proven p146 metadata overflow):
- `syscall(593, ...)` — enumerate all modules, defeat ASLR
- `syscall(626, ...)` — RDMSR, no permission check
- `syscall(639, ...)` — memory region info, no permission check
- `syscall(622, ...)` — device control, 95% unchecked commands
- `syscall(675, ...)` — global state reset, no auth
- `syscall(670, ...)` — cross-process event manipulation
- `syscall(588, ...)` — DMEM page attribute modify, no permission check

---

## FINDING 4: Process Architecture and File System Layout

### Multi-process model
PS5 WebKit uses a multi-process architecture:
- **UIProcess**: Main browser chrome (the PS5 browser app)
- **WebProcess**: `/app0/WebProcess.self` — renders web content
- **NetworkProcess**: `/app0/NetworkProcess.self` — handles network I/O
- **GPUProcess**: `/app0/GPUProcess.self` (disabled by default: `ENABLE_GPU_PROCESS OFF`)

Processes communicate via Unix domain sockets (IPC). Each child process is launched by the proprietary `PlayStation::launchProcess()` API.

### Filesystem
- Application root: `/app0/` (read-only application package)
- Data storage: Falls back to `/app0/` for cache and website data directories
- The `--wrap=access`, `--wrap=lstat`, `--wrap=getcwd` suggest Sony intercepts filesystem operations to enforce a virtual filesystem boundary — but this is application-level, not kernel-level

### Process identity
The process path `/app0/WebProcess.self` means the WebProcess is a separate `.self` executable (signed ELF). Its authId and capabilities are set by the signing metadata, not by runtime code. The WebProcess likely has LOWER privileges than the UIProcess — but we cannot determine the exact authId without the signed binary.

---

## FINDING 5: Mount Operations and sys 630 Relevance

### No direct mount operations from WebKit
The WebKit source contains NO mount/unmount/nmount calls in PlayStation-specific code. However:

1. **Module loading triggers mount-like operations**: Each `dlopen()` / `sceKernelLoadStartModule()` may internally use mount table entries (sys 630's mount tree) to resolve module paths
2. **The WebProcess accesses `/app0/`**: This is a mounted filesystem. sys 630's enumeration functions (which have ZERO priv_check) can reveal the mount topology
3. **Cross-PID mount lookup**: sys 630's cross-process mount lookup by PID (no priv_check) means the WebProcess can map mount namespaces of system daemons

### Storage mounting
WebKit's IndexedDB, localStorage, and cache paths all resolve under `/app0/`. If the user triggers media playback (MSE/EME), the mediaplayer library may trigger additional mount operations for DRM content, potentially creating new mount points visible to sys 630's enumeration.

---

## FINDING 6: CSP/Sandbox Attribute Does NOT Touch Kernel Jail

### HTML sandbox attribute
The `<iframe sandbox>` attribute and CSP `sandbox` directive are handled entirely within WebKit's DOM/security layer (Source/WebCore/page/csp/ContentSecurityPolicy.cpp). They restrict JavaScript capabilities (script execution, form submission, popups) but have ZERO interaction with the kernel jail system.

Relaxing `<iframe sandbox>` attributes from JavaScript (e.g., via DOM manipulation after code execution) does not change kernel process attributes.

---

## FINDING 7: Dynamic import() and Module Loading — No Kernel dynlib Exposure

JavaScript `import()` and ES module loading are handled by JSC's module loader (Source/JavaScriptCore/runtime/JSModuleLoader.cpp), which fetches modules via HTTP/network, NOT via `dlopen()` or kernel dynlib syscalls. There is no path from JavaScript `import()` to kernel module loading.

However, the JSC shell's PlayStation initializer (Source/JavaScriptCore/shell/playstation/Initializer.cpp) loads native modules at startup:
```cpp
loadLibraryOrExit("SystemServices");
loadLibraryOrExit("Perf");
loadLibraryOrExit("PosixWebKit");
loadLibraryOrExit("libJavaScriptCore");
loadLibraryOrExit(ICU_LOAD_AT);
```
These are loaded BEFORE any JavaScript executes, creating additional modules whose bases are leaked by sys 593.

---

## EXPLOITATION CHAIN: WebKit Code Exec to Kernel

```
Step 0: WebKit Exploit (PROVEN — p146 metadata overflow)
  OOB write in WebProcess → arbitrary code execution in WebProcess

Step 1: ASLR Defeat (FREE — no privileges needed)
  syscall(593, handle, &info, sizeof(info), ...)  // dynlib_get_info_ex
  → Extract mapbase for ALL 15+ loaded .sprx modules
  → Build ROP chain from known gadget offsets in libJavaScriptCore/libWebKit
  OR: syscall(612, ...) / syscall(649, ...)  // module member leak, zero priv_check

Step 2: Determine Sandbox Status
  Read td->0x140 to check if process is jailed (likely NOT jailed)
  syscall(630, ...) enumerate → map all kernel mount points (zero priv_check)
  syscall(639, ...) → memory region info → kernel address layout

Step 3: Privilege Escalation
  syscall(622, ...) → 95% unchecked device commands (534 of 561)
  syscall(588, ...) → DMEM page attribute modify → W^X bypass
  syscall(675, ...) → global state reset → clear module validation

Step 4: Kernel R/W Primitive
  Use stack clash (sys 661/662) or sys 588 page attribute flip
  OR: sys 565/566 PTE manipulation (if ucred allows)
  → Modify ucred cr_sceCaps → max privileges

Step 5: Full System Access
  syscall(629, arg0=1) → jail bypass (if jailed, which is unlikely)
  syscall(630, ...) → unrestricted mount operations
  → Persistent kernel patches
```

---

## KEY ANSWERS TO RESEARCH QUESTIONS

**Q: Is the PS5 browser process running inside a FreeBSD jail?**
A: PROBABLY NOT. The WebKit source shows zero jail configuration. The sandbox is implemented via Sony's proprietary ucred extensions (authId + capabilities), not FreeBSD jail. However, the proprietary process launcher (`PlayStation::launchProcess()`) and the process signing metadata are not in the open source — Sony COULD jail processes at the OS level.

**Q: Does the browser use dynlib_get_info_ex (sys 593) for module enumeration?**
A: The browser itself does not call sys 593, but it LOADS 15+ modules via dlopen() which creates entries queryable by sys 593. After code execution, calling sys 593 directly yields FULL ASLR bypass for every loaded module — mapbase, text_size, data_base_off, init_proc_addr, fini_proc_addr all copied WITHOUT privilege check.

**Q: Can we call syscall() directly after code execution?**
A: YES. There is no system call filter (no seccomp, no capsicum, no pledge). The linker wraps (--wrap=mmap etc.) are application-level and do not prevent direct `syscall()` invocation. The only barriers are per-syscall privilege checks, which many critical syscalls lack entirely.

**Q: What modules are loaded in the WebProcess?**
A: At minimum 15+ modules: ICU, PNG, JPEG, WebP, Brotli, FreeType, Fontconfig, HarfBuzz, Cairo, LibPSL, LibXml2, WebKitRequirements, WPE, JavaScriptCore, WebKit. Plus system libraries (libc, kernel). Each one's base address is leaked by sys 593.

---

## FINDING 8: Additional Sony Proprietary Modules in WebProcess (from GPU agent)

The GPU pathway agent identified additional Sony-proprietary binary .sprx modules loaded into the WebProcess:

1. **canvas.sprx** -- Sony display surface API (canvas::Canvas, canvas::IndirectCanvas, canvas::CanvasUtil), used by AcceleratedSurfacePlayStation, TextureMapperGL, MediaPlayer
2. **mediaplayer.sprx** -- Sony media decode backend (PSMediaPlayerBackend), used by MediaPlayerPrivatePlayStation
3. **VBlankMonitor.sprx** -- Display vsync monitor, used by AcceleratedSurfacePlayStation
4. **EGL/GLES implementation** -- Sony's EGL/OpenGL ES .sprx
5. **slimglipc** -- GL IPC mechanism (slim GL IPC), found in cmake config

These are ALL loaded into the WebProcess (not a separate GPU process, since GPU_PROCESS is disabled). This brings the total loaded module count to 20+ .sprx modules, all with base addresses leaked by sys 593 (dynlib_get_info_ex).

## FINDING 9: Gigacage DISABLED on PS5 (from memory agent)

The process/memory pathway agent confirmed: Gigacage is DISABLED on PS5. The bmalloc GIGACAGE_ENABLED macro requires BOS(DARWIN) || BOS(LINUX), but PlayStation uses __SCE__ which matches neither. ArrayBuffer backing stores are NOT caged -- OOB from the p146 metadata overflow reaches arbitrary heap objects without containment.

Combined with the lack of syscall filtering, this makes the full chain viable:
metadata overflow -> uncaged heap corruption -> ROP/code exec -> direct syscall() access

## FINDING 10: IPMI Accessible from WebProcess (from IPMI agent)

The IPMI pathway agent confirmed: The WebProcess links libSceNKWebKitRequirements which internally uses IPMI (sys 622) to communicate with system daemons. Therefore the WebProcess ucred MUST include IPMI permission. Post-exploit syscall(622, ...) works with zero additional barriers -- 534 of 561 commands are unchecked.

---

## 14.10 SURVIVABILITY

All findings are STRUCTURAL:
- The empty sandbox initialization is architectural — Sony would need to add an entirely new sandbox mechanism
- The module loading via dlopen() is fundamental to WebKit's architecture on PlayStation
- The missing privilege checks in sys 593/612/649/630/639/675 are design oversights, not patchable without ABI breaks
- The lack of system call filtering is a platform design choice

The only realistic mitigation Sony could apply is adding priv_check gates to the information-leak syscalls (593, 612, 639), which would require updating all legitimate callers.
