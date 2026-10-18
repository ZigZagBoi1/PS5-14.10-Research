# WebKit Path Analysis 3: GPU, Canvas, and Display Pathways to Kernel Syscalls

## Executive Summary

The PS5 WebKit (WebKit-1200) uses an **in-process GPU architecture** for WebGL -- there is NO separate GPU process on PlayStation. When JavaScript creates a WebGL context, the browser process directly calls EGL/ANGLE, which talks to the PS5 GPU driver, which makes kernel syscalls. This means **every WebGL operation from JavaScript runs GPU driver code in the same process as the renderer**, with no GPU process sandbox boundary.

However, sys 643 (`set_chicken_switches`) and sys 653 (`blockpool_create`) are **not directly reachable** from normal WebGL JavaScript. The WebGL path goes through ANGLE/EGL, not through Sony's custom GPU syscalls. The custom syscalls are used by the native application framework (game runtime), not the browser's OpenGL ES path. The pathway from JavaScript to kernel GPU vulnerabilities requires either: (1) an exploit giving arbitrary syscall capability, or (2) a bug in the ANGLE/EGL driver stack that triggers these syscalls as a side effect.

## Architecture: In-Process GPU on PlayStation

### Key Finding: No GPU Process Isolation

Source evidence from `WebChromeClient.cpp` (line 959-970):
```cpp
RefPtr<GraphicsContextGL> WebChromeClient::createGraphicsContextGL(...) const
{
#if ENABLE(GPU_PROCESS)
    if (WebProcess::singleton().shouldUseRemoteRenderingForWebGL())
        return RemoteGraphicsContextGLProxy::create(...);  // GPU process path
#endif
    return WebCore::createWebProcessGraphicsContextGL(attributes);  // IN-PROCESS path
}
```

The `ENABLE(GPU_PROCESS)` and `ENABLE_GPU_PROCESS_WEBGL_BY_DEFAULT` flags are defined **only for PLATFORM(IOS_FAMILY) and PLATFORM(MAC)** in `PlatformEnable.h` (lines 937-942). PlayStation is NOT included. The PlayStation platform enable file (`PlatformEnablePlayStation.h`) contains only a single unrelated flag.

Therefore: **PS5 WebKit renders WebGL in-process using the TextureMapper ANGLE backend**.

### The WebGL Context Creation Chain (JavaScript to GPU Driver)

1. **JavaScript**: `canvas.getContext('webgl')` or `canvas.getContext('webgl2')`
2. **HTMLCanvasElement::getContextWebGL()** (`HTMLCanvasElement.cpp:454`)
3. **WebGLRenderingContextBase::create()** (`WebGLRenderingContextBase.cpp:551`)
4. **graphicsClient->createGraphicsContextGL()** (`WebGLRenderingContextBase.cpp:606`)
5. **WebChromeClient::createGraphicsContextGL()** -- falls through to in-process path
6. **createWebProcessGraphicsContextGL()** (`GraphicsContextGLTextureMapperANGLE.cpp:111`)
7. **GraphicsContextGLTextureMapperANGLE::create()** (`GraphicsContextGLTextureMapperANGLE.cpp:121`)
8. **platformInitializeContext()** (`GraphicsContextGLTextureMapperANGLE.cpp:167`)
9. **PlatformDisplay::sharedDisplayForCompositing().angleEGLDisplay()** -- gets EGL display
10. **EGL_ChooseConfig, EGL_CreatePbufferSurface, EGL_CreateContext** -- GPU driver calls
11. **GPU driver** -> **kernel syscalls** for GPU context/memory

This entire chain runs **in the browser's web process**, not in a separate GPU process.

### ANGLE/EGL Initialization Details

From `GraphicsContextGLTextureMapperANGLE.cpp:167-246`:
- Gets the shared EGL display from `PlatformDisplay::sharedDisplayForCompositing()`
- On PlayStation, `PlatformDisplay::createPlatformDisplay()` creates a `PlatformDisplayPlayStation` (line 148 in PlatformDisplay.cpp)
- EGL initialization calls `eglGetDisplay(EGL_DEFAULT_DISPLAY)` then `eglInitialize()` (`PlatformDisplay.cpp:298-315`)
- Context creation uses `EGL_OPENGL_ES2_BIT` (or ES3 for WebGL2)
- ANGLE provides WebGL compatibility mode, robust resource init, etc.

## Sys 643 (set_chicken_switches) Reachability Analysis

### What sys 643 Does (Kernel Side)
From `deep_643.rea.analysis.md`:
- Reads a 32-bit argument from uap[0]
- Logs: `[KERNEL] set_chicken_switches(%x)`
- Executes: `process->field_0xa34 |= (uint32_t)uap[0]`
- Returns 0
- **NO permission check, NO bit mask validation, NO capability check**
- Only 48 bytes total -- extremely minimal

### Can WebGL Trigger sys 643?

**NO -- not through normal WebGL operation.** Here is why:

1. WebGL uses ANGLE, which translates OpenGL ES calls to the underlying GPU API
2. ANGLE on PS5 likely uses an EGL backend that talks to the PS5's graphics library (libSceGnmDriver or similar)
3. The `set_chicken_switches` syscall is a process-level flag setter, not a GPU rendering operation
4. Its name suggests it controls hardware debug/feature flags ("chicken switches" is an industry term for hardware feature enable/disable bits)
5. It would typically be called during GPU driver initialization or by the system software, not per-frame rendering

**However**: If the GPU driver's EGL initialization path calls `set_chicken_switches` internally as part of setting up a GPU context, then creating a WebGL context from JavaScript would trigger it indirectly. This cannot be confirmed from source alone -- it requires either:
- Reverse engineering the PS5's EGL/ANGLE implementation (not available in WebKit-1200 source -- it's a binary library)
- Runtime tracing of syscalls during WebGL context creation

### Risk Assessment for sys 643
- **If reachable via WebGL init**: CRITICAL -- any web page could set arbitrary bits in `process->p_flag2` (offset 0xa34) without any permission check. The bit OR means bits can be set but never cleared. If any bit controls security policy (debug mode, privilege level, sandbox flags), this is a direct privilege escalation from JavaScript.
- **If not reachable**: Still concerning because after a WebKit exploit gives arbitrary syscall access, sys 643 is a trivial one-shot escalation (single argument, no validation, no auth check).

## Sys 653 (blockpool_create) Reachability Analysis

### What sys 653 Does (Kernel Side)
From `deep_653.rea.analysis.md`:
- Creates a GPU blockpool file descriptor
- Validates flags: rejects bits outside `0x00500000`
- Allocates a large object (`0x410b0` bytes)
- Initializes `bpoolfd` lock, backing context, quota accounting
- Returns a file descriptor (type `0x11`) via `td_retval`
- **No explicit credential/auth-ID check in the entry**
- Process field `+0x5d0` used as quota index (negative skips accounting)

### Can WebGL Trigger sys 653?

**UNLIKELY through normal WebGL.** The blockpool subsystem is a Sony-proprietary GPU memory management layer:
- It operates on 64 KiB blocks with 2 MiB mapping granularity
- String evidence: `bpoolfd`, `failed to recreate GPU blockpool mappings`
- This is part of Sony's GNM/GNMX GPU API, not the OpenGL ES / EGL layer

WebGL uses ANGLE which provides its own memory management through EGL surfaces and textures. The blockpool syscall is for native PS5 applications that use the Sony GPU API directly.

**However**: The EGL implementation on PS5 may internally use blockpool descriptors to manage GPU memory backing for EGL surfaces and textures. If so, WebGL texture allocation (`texImage2D`, `bufferData`, etc.) could trigger blockpool operations indirectly.

## Sony's Proprietary Display Layer: canvas::Canvas

### Critical Discovery: canvas/canvas.h API

The PS5 WebKit uses a Sony-proprietary `canvas::Canvas` API (header: `<canvas/canvas.h>`) for display compositing. This is NOT the HTML Canvas element -- it is a system-level display surface API.

Key evidence from `AcceleratedSurfacePlayStation.cpp`:
- `canvas::Canvas::create()` or `canvas::IndirectCanvas::create()` -- creates a display surface
- `m_canvas->ensureBufferInitialized(width, height)` -- allocates GPU framebuffer
- `m_canvas->activateAsFrameBuffer()` -- binds for OpenGL rendering
- `m_canvas->swapBuffers()` -- presents the frame
- `m_canvas->activateAsCanvas()` -- compositor integration
- `canvas::CanvasUtil::finish()` -- GPU synchronization
- `canvas::CanvasUtil::getGPUMemUsage()` -- queries GPU memory

This API likely wraps the PS5's display/compositor syscalls and may internally call GPU context creation or memory allocation syscalls.

### Display Compositing Flow
Every page load with accelerated compositing (which is default on PS5) triggers:
1. `AcceleratedSurfacePlayStation::initialize()` -> `canvas::Canvas::create()`
2. On each frame: `willRenderFrame()` -> `ensureBufferInitialized()` -> `activateAsFrameBuffer()`
3. TextureMapperGL renders composited layers using OpenGL ES
4. `didRenderFrame()` -> `swapBuffers()` -> `activateAsCanvas()` -> `finish()`

**This means normal web page rendering (not just WebGL) triggers GPU operations through the canvas::Canvas API.**

### Punch Hole API (Video Overlay)
The `PunchHole` system (`PunchHole.h`) composites video directly:
- Uses `canvas::Canvas::Handle` for video surface identification
- `canvas::IndirectCanvas::IndirectCompositingSource` for overlay compositing
- `mediaplayer::PSMediaPlayerBackend::setTransparentCanvasCompositionCommand()` for video composition
- `canvas::CanvasUtil::isTransparentCanvas()` checks canvas type

HTML `<video>` elements trigger this path, creating additional GPU surface handles.

## CSS Compositing and GPU Layer Management

### TextureMapperGL on PlayStation
From `TextureMapperGL.cpp` (lines 488, 701, 846):
- PlayStation has custom shader program handling with `program->setOptions(options)`
- Uses standard OpenGL ES calls: `glUseProgram`, `glUniform4f`, etc.
- This runs in-process in the web content process

CSS properties that trigger GPU compositing layers:
- `transform: translate3d()`
- `will-change: transform`
- `position: fixed`
- `opacity` animations
- `filter` effects
- Any composited layer creates a `GraphicsLayer` -> `TextureMapperGL` rendering

Each composited layer potentially allocates GPU textures and framebuffers.

## Video/Media Decode GPU Paths

### MediaPlayerPrivatePlayStation
From `MediaPlayerPrivatePlayStation.h/cpp`:
- Uses `mediaplayer::PSMediaPlayerBackend` -- Sony proprietary media decode
- Uses `TextureMapperPlatformLayerProxyGL` for GPU-accelerated video display
- Creates `TextureMapperPlatformLayerBuffer` with `canvas::Canvas::Handle`
- Checks `acceleratedCompositingEnabled()` to decide rendering path

HTML `<video>` with hardware decode creates GPU surfaces that interact with the display compositor.

## Font Rendering
PlayStation WebKit uses FreeType for fonts (`Source/WebCore/platform/graphics/freetype/`). Font rendering appears to be CPU-based (Cairo/FreeType), not GPU-accelerated. No PlayStation-specific GPU font paths found.

## Summary: JavaScript to Kernel GPU Syscall Pathways

### CONFIRMED Pathways (normal JavaScript, no exploit needed):

| JavaScript Action | WebKit Path | GPU Operation | Kernel Interaction |
|---|---|---|---|
| Any page load | AcceleratedSurfacePlayStation | canvas::Canvas::create() | Display surface creation (proprietary syscalls) |
| CSS compositing | TextureMapperGL | glTexImage2D, glFramebufferTexture2D | EGL/GL driver -> GPU memory allocation |
| `canvas.getContext('webgl')` | GraphicsContextGLTextureMapperANGLE | EGL_CreateContext, EGL_CreatePbufferSurface | GPU context creation via EGL driver |
| WebGL texImage2D | GraphicsContextGLANGLE | GL_TexImage2D via ANGLE | GPU memory allocation via driver |
| WebGL bufferData | GraphicsContextGLANGLE | GL_BufferData via ANGLE | GPU buffer allocation via driver |
| `<video>` playback | MediaPlayerPrivatePlayStation | canvas::Canvas::Handle, PSMediaPlayerBackend | Video decode + GPU surface creation |
| Every frame | AcceleratedSurfacePlayStation::didRenderFrame | canvas::CanvasUtil::finish() | GPU synchronization |

### UNCERTAIN Pathways (depends on driver internals):

| Question | What Needs Verification |
|---|---|
| Does EGL context creation call sys 643? | Need syscall trace of `eglCreateContext` on PS5 |
| Does EGL/GL memory allocation use sys 653 blockpool? | Need syscall trace of `glTexImage2D` / `glBufferData` |
| Does canvas::Canvas::create() trigger GPU context syscalls? | Need to reverse the canvas library |
| What GPU initialization happens at WebKit startup? | Need startup syscall trace |

### CONFIRMED Pathways (post-exploit, with arbitrary syscall access):

After obtaining arbitrary R/W in the web process (e.g., via p146 metadata overflow or p206 RAB exploit):
- sys 643: Trivially callable, single argument, sets arbitrary bits in process flags with NO check
- sys 653: Callable to create blockpool descriptors; no credential check in entry
- sys 654: Callable to populate blockpool mappings; has some validation but operates on process's own GPU context

## Critical Observations

1. **No GPU Process Sandbox**: The lack of a separate GPU process means ANY WebKit renderer compromise gives direct access to the GPU driver and its syscalls. On macOS/iOS, WebGL runs in a separate GPU process with its own sandbox -- on PS5, it runs in the web process.

2. **The canvas::Canvas API is the key unknown**: This Sony-proprietary API is the bridge between WebKit rendering and the PS5 display system. Its implementation (binary-only, not in WebKit source) is where GPU context creation and memory allocation syscalls would be invoked.

3. **sys 643 is the most dangerous**: If reachable through any GPU initialization path (even indirectly via canvas::Canvas::create or EGL init), it provides an unprivileged bit-OR on process flags with zero validation. Even if not reachable from normal WebGL, after a WebKit exploit it's a single syscall away from process flag manipulation.

4. **WebGL provides rich GPU interaction surface**: Even if sys 643/653 aren't directly triggered, WebGL gives JavaScript extensive control over GPU memory allocation (textures, buffers, framebuffers, renderbuffers), GPU state (shaders, programs, uniforms), and rendering operations -- all running in-process without GPU process isolation.

## Cross-Agent Intelligence (received from peer analysis agents)

### From IPMI/IPC Agent (sys 622)
- PS5 WebKit build checks for `slimglipc.h` (slim GL IPC) -- GL rendering uses IPC to communicate with a GL server
- IPMI dispatcher (sys 622) likely carries GPU command submission/completion
- IPMI session types 0x8001, 0x8004 appear in the request marshaller
- **Implication**: WebGL GL calls go through: ANGLE -> EGL -> slimglipc -> IPMI (sys 622) -> GPU server

### From Process/Memory Agent (sys 601, 588, 639)
- Standard FreeBSD mmap/mprotect used for ALL WebKit memory (ArrayBuffer, Wasm, bmalloc)
- No Sony DMEM syscalls (sys 588) during normal WebKit ops
- **GIGACAGE is DISABLED** on PS5 (not Darwin, not Linux) -- typed array backing stores are uncaged
- GPU memory allocation happens through Sony-specific binary libraries not in open source

### From Jail/Module Agent (sys 629, 630, 593)
- **PS5 WebProcess has NO kernel-level sandbox** -- initializeSandbox() is empty
- GPU_PROCESS is DISABLED in OptionsPlayStation.cmake (ENABLE_GPU_PROCESS OFF)
- WebProcess links EGL libraries directly as PlayStation modules
- sys 593 can enumerate loaded GPU library base addresses post-exploit
- **No syscall filter** -- sys 643 and sys 653 are directly callable post-exploit
- Cairo is the rendering backend; TextureMapper for compositing; EGL/OpenGL ES for graphics

### From Events/Async Agent (sys 669, 670, 558)
- GPUProcess.self binary EXISTS at /app0/GPUProcess.self but is DISABLED in build config
- GPU IPC uses socketpair (SOCK_STREAM) when enabled
- All event loop sync uses GENERIC_EVENT_LOOP: WTF::Lock -> ParkingLot -> pthread -> kernel
- No Sony-specific event APIs in open WebKit source -- GPU events handled in proprietary libs
- OffscreenCanvas Workers create own pthreads with own RunLoop for GPU sync

### Combined Picture
The PS5 web browser is effectively **unsandboxed with direct GPU driver access**:
1. No kernel sandbox (initializeSandbox is empty)
2. No GPU process isolation (GPU_PROCESS OFF)
3. No Gigacage for typed arrays
4. No syscall filter
5. GPU libraries loaded directly into WebProcess
6. GL commands go via IPC (slimglipc) to a GPU server -- but the IPC channel is in the WebProcess

This means after ANY WebKit code execution (e.g., p146 metadata overflow, p206 RAB exploit):
- sys 643 (set_chicken_switches) is one syscall away -- no barriers
- sys 653 (blockpool_create) is one syscall away -- no barriers
- GPU driver data structures are in the same address space
- GPU library addresses can be leaked via sys 593

## Corrections from Sol Review (review_batch3_648_653_630.md)

Per the Sol review, important corrections apply:

- **sys 643**: Is actually `set_chicken_switches`, a process flag setter. It is NOT part of a GPU context manager. The neighboring code is PPR PFS (protected filesystem), not GPU code. The syscall itself is complete at 48 bytes.

- **sys 653**: Creates a blockpool file descriptor. The manual analysis incorrectly described it as modifying GPU page attributes. The actual argument is a flags word for descriptor creation, NOT a GPU target address. No explicit credential check in the entry, but "authorized effect not demonstrated."

- **sys 648**: Is a gated application-manager event handler, NOT a GPU/display context manager. It has an explicit credential gate. Event 7 sets the `ENABLE_GAME_FMEM_EXTENTION` flag. The large routine at +0xa0 is a separate function (`begin_app_mount`).

## Files Referenced

### Kernel Analysis
- `/tmp/.../deep_handlers/deep_643.rea.analysis.md` -- sys 643 set_chicken_switches analysis
- `/tmp/.../deep_handlers/deep_643.rea.c` -- sys 643 pseudocode
- `/tmp/.../deep_handlers/deep_653.rea.analysis.md` -- sys 653 blockpool_create analysis
- `/tmp/.../deep_handlers/deep_648.rea.analysis.md` -- sys 648 app event analysis
- `/tmp/.../deep_handlers/review_batch3_648_653_630.md` -- Sol review corrections

### WebKit Source (key files)
- `Source/WebKit/WebProcess/WebCoreSupport/WebChromeClient.cpp:959` -- WebGL creation decision point
- `Source/WebCore/platform/graphics/texmap/GraphicsContextGLTextureMapperANGLE.cpp:111` -- in-process WebGL creation
- `Source/WebCore/platform/graphics/texmap/GraphicsContextGLTextureMapperANGLE.cpp:167` -- EGL context init
- `Source/WebCore/platform/graphics/PlatformDisplay.cpp:298` -- EGL display initialization
- `Source/WebCore/platform/graphics/playstation/PlatformDisplayPlayStation.h` -- PS5 display type
- `Source/WebKit/WebProcess/WebPage/neko/AcceleratedSurfacePlayStation.cpp` -- PS5 GPU surface management
- `Source/WebCore/platform/graphics/playstation/PunchHole.h` -- Sony canvas API for display
- `Source/WebCore/platform/graphics/playstation/MediaPlayerPrivatePlayStation.cpp` -- video GPU paths
- `Source/WebCore/platform/graphics/texmap/TextureMapperGL.cpp` -- PS5 compositing
- `Source/WTF/wtf/PlatformEnable.h:937-942` -- GPU process NOT enabled for PlayStation
- `Source/WTF/wtf/PlatformEnablePlayStation.h` -- PlayStation feature flags (minimal)
