-- CRASH_CLASS: LOW
-- PROBE 947b: mlfs inode lifetime - open, unlink, truncate, rename
--
-- Context: 947a showed the mlfs entry points behave on ordinary shapes (sparse
-- write, 1 GiB truncate, rename over, 255-byte names, getdents).  The next
-- question is object lifetime, which is where filesystem bugs actually live:
-- does an unlinked-but-open inode stay usable, does a second descriptor see a
-- truncate, does a rename move the inode or copy it, and does reopening a name
-- after unlink create a *new* object rather than resurrecting the old one.
--
-- All of this is single-threaded and uses only paths and lengths we created, so
-- it cannot fault on an unmapped page.  A wrong refcount shows up as a read
-- returning the old data (or a fault); a correct one shows up as EOF/zeros.

print("=== PROBE 947b: MLFS INODE LIFETIME ===")
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
local sc_open, sc_write, sc_read, sc_close = mk(5), mk(4), mk(3), mk(6)
local sc_lseek, sc_unlink, sc_ftrunc, sc_rename = mk(478), mk(10), mk(480), mk(128)
local sc_mmap, sc_munmap = mk(477), mk(73)

local buf = call(function() return sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
if not buf or buf <= 0 then print("[!] no buffer"); return end
print("[0] buffer=0x" .. string.format("%X", buf))

local function fill(v)
    for i = 0, 0x3F do pcall(function() memory.write_dword(buf + i * 4, v + i) end) end
end
local function peek(off)
    local ok, v = pcall(function() return memory.read_dword(buf + off) end)
    if ok then return to_num(v) end
    return nil
end
local function wr(fd, n)
    return call(function() return sc_write(uint64(fd), uint64(buf), uint64(n)) end)
end
local function rd(fd, n)
    return call(function() return sc_read(uint64(fd), uint64(buf + 0x2000), uint64(n)) end)
end
local function seek(fd, off)
    return call(function() return sc_lseek(uint64(fd), uint64(off), uint64(0)) end)
end

local function canary(tag)
    local p = call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
    if p ~= pid then print(string.format("[!] DEAD after %s", tag)) return false end
    return true
end

-- A: unlink while open, then keep using the descriptor
print("[A] unlink while open")
local p1 = base .. "l947a.bin"
local fd = call(function() return sc_open(p1, uint64(0x602), uint64(0x1FF)) end)
print("  open = " .. tostring(fd))
fill(0x11110000)
print("  write 0x100 = " .. tostring(wr(fd, 0x100)))
print("  unlink = " .. tostring(call(function() return sc_unlink(p1) end)))
print("  write 0x40 after unlink = " .. tostring(wr(fd, 0x40)))
print("  seek 0 = " .. tostring(seek(fd, 0)))
print("  read 0x40 = " .. tostring(rd(fd, 0x40)))
local v = peek(0x2000)
print(string.format("  data after unlink = 0x%08X (expect 0x11110000)", v or 0))
print("  close = " .. tostring(call(function() return sc_close(uint64(fd)) end)))
if not canary("A") then return end

-- B: reopen the same name after unlink - must be a new, empty object
print("[B] reopen after unlink")
local fd2 = call(function() return sc_open(p1, uint64(0x602), uint64(0x1FF)) end)
print("  open = " .. tostring(fd2))
print("  read at 0 = " .. tostring(rd(fd2, 0x40)))
print("  read returns 0 => new empty inode, >0 => old data resurrected")
call(function() return sc_close(uint64(fd2)) end)
if not canary("B") then return end

-- C: two descriptors, one truncates, the other reads
print("[C] truncate through a second descriptor")
local p2 = base .. "l947c.bin"
local fa = call(function() return sc_open(p2, uint64(0x602), uint64(0x1FF)) end)
fill(0x22220000)
print("  write 0x200 = " .. tostring(wr(fa, 0x200)))
local fb = call(function() return sc_open(p2, uint64(0x2), uint64(0)) end)
print("  second open = " .. tostring(fb))
print("  ftruncate(fb,0) = " .. tostring(call(function() return sc_ftrunc(uint64(fb), uint64(0)) end)))
print("  seek(fa,0) = " .. tostring(seek(fa, 0)))
local n = rd(fa, 0x40)
print("  read via first fd after truncate = " .. tostring(n))
print("  (0 = both see the truncate, 0x40 = stale data)")
print("  write -1 style check: ftruncate(fb, 0x8000000000000000) = " ..
    tostring(call(function() return sc_ftrunc(uint64(fb), uint64(0x8000000000000000)) end)))
call(function() return sc_close(uint64(fa)) end)
if type(fb) == "number" and fb >= 0 then call(function() return sc_close(uint64(fb)) end) end
if not canary("C") then return end

-- D: rename while open, read and write through the descriptor afterwards
print("[D] rename while open")
local p3, p4 = base .. "l947d.bin", base .. "l947e.bin"
local fd3 = call(function() return sc_open(p3, uint64(0x602), uint64(0x1FF)) end)
fill(0x33330000)
print("  write = " .. tostring(wr(fd3, 0x80)))
print("  rename = " .. tostring(call(function() return sc_rename(p3, p4) end)))
print("  seek 0 = " .. tostring(seek(fd3, 0)))
print("  read = " .. tostring(rd(fd3, 0x80)))
local v3 = peek(0x2000)
print(string.format("  data after rename = 0x%08X (expect 0x33330000)", v3 or 0))
print("  open old name = " .. tostring(call(function() return sc_open(p3, uint64(0), uint64(0)) end)))
print("  open new name = " .. tostring(call(function() return sc_open(p4, uint64(0), uint64(0)) end)))
call(function() return sc_close(uint64(fd3)) end)
call(function() return sc_unlink(p4) end)
if not canary("D") then return end

call(function() return sc_munmap(uint64(buf), uint64(0x4000)) end)
print("")
print("=== PROBE 947b COMPLETE ===")
