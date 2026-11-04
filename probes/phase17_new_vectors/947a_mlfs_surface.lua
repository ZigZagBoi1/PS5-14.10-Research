-- CRASH_CLASS: MODERATE
-- PROBE 947a: mlfs (Sony filesystem) surface on a writable path
--
-- Context: /av_contents/content_tmp is the one place we can create files
-- (939c), which makes Sony's filesystem implementation the only kernel parser
-- that consumes data we fully control - file contents, sizes, offsets and
-- names - without a capability gate.  Nothing in the repository has ever
-- stressed it: 930a only asked which paths exist, 939b/939c only mapped a file.
--
-- This probe drives the ordinary VFS calls with adversarial-but-legal shapes:
-- a sparse write far past EOF, a truncate larger than the file, a 255-byte
-- name, mkdir/rmdir, rename over an existing file, and a getdents read.  Every
-- call is reported; a getpid canary after each group says whether the process
-- is still the same one.
--
-- Nothing here reads unmapped memory - the loader dies on a userland fault even
-- inside pcall - so every read-back is bounded by what was written.

print("=== PROBE 947a: MLFS SURFACE ===")
print("")

local function to_num(v)
    if type(v) == "table" then
        if v.tonumber then local n = v:tonumber() if n then return n end end
        if v.h then return v.h * 4294967296 + v.l end
    end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function call(f, ...)
    local ok, rv = pcall(f, ...)
    if not ok then return nil end
    return to_num(rv)
end

local pid = call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
print("[0] pid=" .. tostring(pid))

local base = "/av_contents/content_tmp/"
local path = base .. "m947.bin"
local sc_open, sc_write, sc_close = mk(5), mk(4), mk(6)
local sc_lseek, sc_ftrunc, sc_rename = mk(478), mk(480), mk(128)
local sc_unlink, sc_mkdir, sc_rmdir = mk(10), mk(136), mk(137)
local sc_mmap, sc_munmap = mk(477), mk(73)

local buf = call(function() return sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
if not buf or buf <= 0 then print("[!] no buffer page"); return end
for i = 0, 0x3FF do pcall(function() memory.write_dword(buf + i * 4, 0xC0DE0000 + i) end) end
print("[0] buffer=0x" .. string.format("%X", buf))

local function canary(tag)
    local p = call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
    if p ~= pid then print(string.format("[!] DEAD after %s", tag)) return false end
    return true
end

-- A: create, write, sparse write far past EOF, read back through pread-style lseek
print("[A] create + sparse write")
local fd = call(function() return sc_open(path, uint64(0x202), uint64(0x1FF)) end)
print("  open = " .. tostring(fd))
if type(fd) ~= "number" or fd < 0 then print("[!] no fd"); return end
print("  write 0x1000 @0 = " .. tostring(call(function() return sc_write(uint64(fd), uint64(buf), uint64(0x1000)) end)))
local off = 0x3FFFFF00                      -- ~1 GiB sparse offset, inside off_t
print("  lseek(1GiB) = " .. tostring(call(function() return sc_lseek(uint64(fd), uint64(off), uint64(0)) end)))
print("  write 0x100 @off = " .. tostring(call(function() return sc_write(uint64(fd), uint64(buf), uint64(0x100)) end)))
print("  lseek(0) = " .. tostring(call(function() return sc_lseek(uint64(fd), uint64(0), uint64(0)) end)))
local rd = call(function() return sc_lseek(uint64(fd), uint64(off), uint64(0)) end)
local rv = call(function() return mk(478)(uint64(fd), uint64(off), uint64(0)) end)
print("  seek back to sparse offset = " .. tostring(rv))
print("  read 0x100 = " .. tostring(call(function() return mk(3)(uint64(fd), uint64(buf + 0x2000), uint64(0x100)) end)))
local got = nil
local ok, v = pcall(function() return memory.read_dword(buf + 0x2000) end)
if ok then got = to_num(v) end
print(string.format("  first dword read back = 0x%08X (wrote 0xC0DE0000)", got or 0))
if not canary("A") then return end

-- B: truncate larger than the file, then smaller, then read the tail
print("[B] ftruncate up and down")
print("  ftruncate(0x40000000) = " .. tostring(call(function() return sc_ftrunc(uint64(fd), uint64(0x40000000)) end)))
print("  ftruncate(0x1000) = " .. tostring(call(function() return sc_ftrunc(uint64(fd), uint64(0x1000)) end)))
print("  lseek(0xE00) = " .. tostring(call(function() return sc_lseek(uint64(fd), uint64(0xE00), uint64(0)) end)))
print("  read 0x400 = " .. tostring(call(function() return mk(3)(uint64(fd), uint64(buf + 0x2400), uint64(0x400)) end)))
if not canary("B") then return end

-- C: rename over an existing file, then unlink both names
print("[C] rename over an existing file")
local path2 = base .. "m947b.bin"
local fd2 = call(function() return sc_open(path2, uint64(0x202), uint64(0x1FF)) end)
print("  open second = " .. tostring(fd2))
print("  rename(a->b) = " .. tostring(call(function() return sc_rename(path, path2) end)))
print("  unlink(b) = " .. tostring(call(function() return sc_unlink(path2) end)))
print("  unlink(b) again = " .. tostring(call(function() return sc_unlink(path2) end)))
call(function() return sc_close(uint64(fd)) end)
if type(fd2) == "number" and fd2 >= 0 then call(function() return sc_close(uint64(fd2)) end) end
if not canary("C") then return end

-- D: a 255-byte name, mkdir/rmdir, and a name that is exactly at the boundary
print("[D] long names and directories")
local longname = base .. string.rep("n", 255)
print("  open(255-byte name) = " .. tostring(call(function() return sc_open(longname, uint64(0x602), uint64(0x1FF)) end)))
local dir1 = base .. "d947"
print("  mkdir d947 = " .. tostring(call(function() return sc_mkdir(dir1, uint64(0x1FF)) end)))
print("  rmdir d947 = " .. tostring(call(function() return sc_rmdir(dir1) end)))
if not canary("D") then return end

-- E: getdents on the directory that holds all of this
print("[E] getdents")
local dfd = call(function() return sc_open(base, uint64(0), uint64(0)) end)
print("  open(dir) = " .. tostring(dfd))
if type(dfd) == "number" and dfd >= 0 then
    local sc_gd = mk(272)
    local n = call(function() return sc_gd(uint64(dfd), uint64(buf), uint64(0x1000)) end)
    print("  getdents = " .. tostring(n))
    call(function() return mk(478)(uint64(dfd), uint64(0), uint64(0)) end)
    call(function() return sc_close(uint64(dfd)) end)
end
if not canary("E") then return end

call(function() return sc_munmap(uint64(buf), uint64(0x4000)) end)
print("")
print("=== PROBE 947a COMPLETE ===")
