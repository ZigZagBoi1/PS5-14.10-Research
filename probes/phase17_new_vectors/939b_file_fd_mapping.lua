-- CRASH_CLASS: LOW
-- PROBE 939b: file descriptor, write, and file-backed mapping (no thread spawn)
--
-- Context: 939a died before printing any post-open line, so the file half was
-- never measured.  This probe isolates it and touches no thread context at all:
-- it only asks whether the loader can open a file by path through make_syscall,
-- write bytes into it, and map it back with PROT_EXEC.
--
-- A: pid + harness sanity
-- B: open(/savedata0/xcode.bin, O_RDWR|O_CREAT, 0777)
-- C: write 0x40 bytes of 0xC3 through a normal RW mapping
-- D: mmap(fd, PAGE, prot=5, MAP_PRIVATE) and read the first byte back
-- E: mmap(fd, PAGE, prot=7, MAP_PRIVATE) and read it back
-- F: the same with a read-only file that certainly exists (/savedata0/misc.lua)
--
-- No execution is attempted here; execution is 939c and only runs if D or E
-- produced a mapping.

print("=== PROBE 939b: FILE FD + FILE-BACKED MAPPING ===")
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
local function mmap(px, prot, flags, fd)
    return call(function() return mk(477)(uint64(0), uint64(px), uint64(prot), uint64(flags), uint64(fd), uint64(0)) end)
end

print("[A] pid=" .. tostring(call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)))

local PAGE = 0x4000
local rw = mmap(PAGE, 3, 0x1002, 0xFFFFFFFF)
print("[A] scratch mmap prot=3 -> " .. tostring(rw))
if type(rw) == "number" and rw > 0 then
    for i = 0, 0x3F do pcall(function() memory.write_byte(rw + i, 0xC3) end) end
    local o, v = pcall(function() return memory.read_byte(rw) end)
    print("[A] scratch first byte=" .. tostring(o and to_num(v) or "FAIL"))
end

local name = "/savedata0/xcode.bin"
local fd = call(function() return mk(5)(name, uint64(0x202), uint64(0x1FF)) end)
print(string.format("[B] open(%q, O_RDWR|O_CREAT, 0777) = %s", name, tostring(fd)))

if type(fd) == "number" and fd >= 0 and type(rw) == "number" and rw > 0 then
    print("[C] write(fd, buf, 0x40) = " .. tostring(call(function() return mk(4)(uint64(fd), uint64(rw), uint64(0x40)) end)))

    local m5 = mmap(PAGE, 5, 0x2, fd)
    print("[D] mmap(fd, PAGE, prot=5, MAP_PRIVATE) = " .. tostring(m5))
    if type(m5) == "number" and m5 > 0 then
        local o, v = pcall(function() return memory.read_byte(m5) end)
        print("[D] first byte = " .. tostring(o and to_num(v) or "FAIL") .. " (expect 195)")
    end

    local m7 = mmap(PAGE, 7, 0x2, fd)
    print("[E] mmap(fd, PAGE, prot=7, MAP_PRIVATE) = " .. tostring(m7))
    if type(m7) == "number" and m7 > 0 then
        local o, v = pcall(function() return memory.read_byte(m7) end)
        print("[E] first byte = " .. tostring(o and to_num(v) or "FAIL"))
        local w = call(function() return mk(76)(uint64(m7), uint64(PAGE), uint64(7)) end)
        print("[E] mprotect(m7, PAGE, 7) = " .. tostring(w))
    end
end

local fd2 = call(function() return mk(5)("/savedata0/misc.lua", uint64(0), uint64(0)) end)
print("[F] open(/savedata0/misc.lua, O_RDONLY) = " .. tostring(fd2))
if type(fd2) == "number" and fd2 >= 0 then
    local f5 = mmap(PAGE, 5, 0x2, fd2)
    print("[F] mmap(fd2, PAGE, prot=5, MAP_PRIVATE) = " .. tostring(f5))
    if type(f5) == "number" and f5 > 0 then
        local o, v = pcall(function() return memory.read_byte(f5) end)
        print("[F] first byte = " .. tostring(o and to_num(v) or "FAIL"))
    end
end

-- G: which protection values does mprotect accept at all?
if type(rw) == "number" and rw > 0 then
    local sc = mk(74)
    for _, pr in ipairs({0, 1, 3, 5, 7}) do
        local r = call(function() return sc(uint64(rw), uint64(PAGE), uint64(pr)) end)
        print(string.format("[G] mprotect(rw, PAGE, %d) = %s", pr, tostring(r)))
    end
    local r97 = call(function() return sc(uint64(rw), uint64(0x40), uint64(3)) end)
    print("[G] mprotect(rw, 0x40, 3) = " .. tostring(r97))
end

print("")
print("=== PROBE 939b COMPLETE ===")
