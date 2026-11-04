-- CRASH_CLASS: LOW
-- PROBE 939c: does a file-backed entry's max_prot include PROT_EXEC?
--
-- Context: 939b established three things in one run - open(5) works when the
-- path is passed as a raw Lua string (fd 22 for /savedata0/misc.lua), a
-- file-backed mmap with prot=5 succeeds and returns the file's real bytes, and
-- mprotect accepts 0/1/3 while rejecting 5 and 7 on an anonymous mapping.
--
-- That last pair is the oracle this probe uses: mprotect fails with
-- KERN_PROTECTION_FAILURE when the requested prot exceeds the entry's max_prot.
-- If mprotect(filemap, PAGE, 5) returns 0, the file-backed entry *does* allow
-- execute and the mapping can run our bytes.  If it returns -1, every mapping
-- in this kernel is NX regardless of backing object, and the mmap avenue is
-- closed without spending a crash.
--
-- A: anonymous mapping, mprotect 0/1/3/5/7 (baseline, repeats 939b)
-- B: file mapping of /savedata0/misc.lua, mprotect 0/1/3/5/7
-- C: writable path probe - open(O_RDWR|O_CREAT) under /av_contents/content_tmp
-- D: if C gives an fd, mmap prot=5 and mprotect 7 on it
--
-- No thread is spawned here.

print("=== PROBE 939c: FILE-BACKED max_prot ORACLE ===")
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
    if not ok then return "PCALL-FAIL" end
    return to_num(rv)
end
local sc_mmap, sc_prot, sc_open, sc_write = mk(477), mk(74), mk(5), mk(4)
local PAGE = 0x4000

local function mmap(px, prot, flags, fd)
    return call(function() return sc_mmap(uint64(0), uint64(px), uint64(prot), uint64(flags), uint64(fd), uint64(0)) end)
end
local function sweep(tag, addr, len)
    for _, pr in ipairs({0, 1, 3, 5, 7}) do
        local r = call(function() return sc_prot(uint64(addr), uint64(len), uint64(pr)) end)
        print(string.format("[%s] mprotect(%s, %d) = %s", tag, string.format("0x%X", addr), pr, tostring(r)))
    end
end

print("[0] pid=" .. tostring(call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)))

local anon = mmap(PAGE, 3, 0x1002, 0xFFFFFFFF)
print("[A] anon mmap prot=3 -> " .. tostring(anon))
if type(anon) == "number" and anon > 0 then sweep("A", anon, PAGE) end

local fd = call(function() return sc_open("/savedata0/misc.lua", uint64(0), uint64(0)) end)
print("[B] open(/savedata0/misc.lua) = " .. tostring(fd))
if type(fd) == "number" and fd >= 0 then
    local fm = mmap(PAGE, 5, 0x2, fd)
    print("[B] file mmap prot=5 -> " .. tostring(fm))
    if type(fm) == "number" and fm > 0 then
        local o, v = pcall(function() return memory.read_byte(fm) end)
        print("[B] first byte=" .. tostring(o and to_num(v) or "FAIL"))
        sweep("B", fm, PAGE)
    end
    for _, prot in ipairs({3, 5, 7}) do
        local m = mmap(PAGE, prot, 0x2, fd)
        print(string.format("[B] file mmap prot=%d -> %s", prot, tostring(m)))
    end
end

local tmp = "/av_contents/content_tmp/xcode.bin"
local fdw = call(function() return sc_open(tmp, uint64(0x202), uint64(0x1FF)) end)
print(string.format("[C] open(%q, O_RDWR|O_CREAT) = %s", tmp, tostring(fdw)))
if type(fdw) == "number" and fdw >= 0 then
    local buf = mmap(PAGE, 3, 0x1002, 0xFFFFFFFF)
    if type(buf) == "number" and buf > 0 then
        for i = 0, 7 do pcall(function() memory.write_byte(buf + i, 0xC3) end) end
        print("[C] write = " .. tostring(call(function() return sc_write(uint64(fdw), uint64(buf), uint64(8)) end)))
        local m = mmap(PAGE, 5, 0x2, fdw)
        print("[C] mmap prot=5 -> " .. tostring(m))
        if type(m) == "number" and m > 0 then
            local o, v = pcall(function() return memory.read_byte(m) end)
            print("[C] first byte=" .. tostring(o and to_num(v) or "FAIL"))
            sweep("C", m, PAGE)
        end
    end
end

print("")
print("=== PROBE 939c COMPLETE ===")
