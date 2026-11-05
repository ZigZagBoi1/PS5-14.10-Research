-- CRASH_CLASS: LOW
-- PROBE 929a: is the loader LuaJIT, and does its JIT actually run?
--
-- Why: LuaJIT compiles traces into mcode pages it maps executable itself. If that works on
-- 14.10, W^X has already been bypassed by a runtime we control, and the trace allocator is a
-- JIT-spray target. LuaJIT also disables JIT by itself when mcode allocation fails, so
-- jit.status() after a hot loop answers the question without us calling mprotect at all.
-- FFI would additionally give direct C calls with arbitrary argument types.
print("=== PROBE 929a: LuaJIT surface ===")
local function T(name, v) print(string.format("%-14s %s", name, tostring(v))) end

T("_VERSION", _VERSION)
T("jit", type(jit))
if type(jit) == "table" then
    T("jit.version", jit.version)
    T("jit.version_num", jit.version_num)
    T("jit.arch", jit.arch)
    T("jit.os", jit.os)
    local ok, a, b = pcall(jit.status)
    print(string.format("[1] jit.status ok=%s enabled=%s flags=%s", tostring(ok), tostring(a), tostring(b)))
    T("jit.util", type(jit.util))
    T("jit.opt", type(jit.opt))
else
    print("[1] no jit table: this is PUC Lua, not LuaJIT")
end

local okf, ffi = pcall(require, "ffi")
print(string.format("[2] require('ffi') ok=%s type=%s", tostring(okf), type(ffi)))
if okf and ffi then
    T("ffi.os", ffi.os)
    T("ffi.arch", ffi.arch)
    local okc, C = pcall(ffi.cdef, "int getpid(void);")
    T("ffi.cdef", tostring(okc))
    if okc then
        local okp, pid = pcall(function() return ffi.C.getpid() end)
        print(string.format("[2] ffi.C.getpid ok=%s pid=%s", tostring(okp), tostring(pid)))
    end
end

T("bit", type(bit))
T("bit32", type(bit32))
T("string.dump", type(string and string.dump))

-- hot loop: enough calls for the JIT to compile a trace if it can
local t0 = os.clock and os.clock() or 0
local acc = 0
for i = 1, 3000000 do acc = acc + i end
local t1 = os.clock and os.clock() or 0
print(string.format("[3] hot loop acc=%s clock=%.3f", tostring(acc), t1 - t0))
if type(jit) == "table" then
    local ok, a, b = pcall(jit.status)
    print(string.format("[4] jit.status after loop ok=%s enabled=%s flags=%s", tostring(ok), tostring(a), tostring(b)))
    local okon, e = pcall(jit.on)
    print(string.format("[4] jit.on ok=%s err=%s", tostring(okon), tostring(e)))
    local ok2, a2 = pcall(jit.status)
    print(string.format("[4] jit.status after on enabled=%s", tostring(a2)))
end

-- heap shape, for a spray budget
local kb = collectgarbage("count")
print(string.format("[5] heap KB=%s", tostring(kb)))
print("[Z] COMPLETE")
