-- CRASH_CLASS: HIGH
-- PROBE 945a: isolate syscall 374 (extattr_list_file shape)
--
-- Context: 944a opened /av_contents/content_tmp/extattr_test.bin (fd 22), wrote
-- five bytes, then called 371, 372 and 373 - each returned -1 with no output
-- written - and died at 374 with (path, buf, 0x100, 0).  374 is the only call in
-- that sweep that took the process down, so the next question is which argument
-- makes it fatal: the path, the buffer, the length, or the fourth slot.
--
-- Order matters.  Every shape that should fail early in the handler runs first,
-- the known-lethal shape runs last, and a canary between shapes tells us whether
-- the process survived the one before it.  A crash here costs one relaunch.
--
--   A  374(path, NULL, 0, 0)        no buffer, no length back
--   B  374(path, buf, 1, 0)         one byte of room
--   C  374(0, buf, 0x100, 0)        no path
--   D  374(path, buf, 0, 0)         buffer but zero length
--   E  374(path, buf, 0x100, 0)     the shape that died in 944a
--
-- If A-D return an errno and E dies, the fatal condition is a real buffer plus a
-- real length, i.e. the copyout path, not the name lookup.

print("=== PROBE 945a: SYS 374 ISOLATION ===")
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

local path = "/av_contents/content_tmp/extattr_test.bin"
local sc_open = mk(5)
local fd = call(function() return sc_open(path, uint64(0x202), uint64(0x1FF)) end)
print("[0] open = " .. tostring(fd))

local buf = memory.alloc(0x100)
pcall(function() memory.write_dword(buf, 0xDEADBEEF) end)

local sc374 = mk(374)
local function probe(tag, a1, a2, a3, a4)
    local ret = call(function() return sc374(a1, a2, a3, a4) end)
    print(string.format("  %-28s ret=%s", tag, tostring(ret)))
    local p = call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
    if p ~= pid then print(string.format("[!] DEAD after %s (canary=%s)", tag, tostring(p))) return false end
    return true
end

print("[A] shapes that should fail before copyout")
if not probe("374(path,NULL,0,0)", path, uint64(0), uint64(0), uint64(0)) then return end
if not probe("374(path,buf,1,0)", path, uint64(buf), uint64(1), uint64(0)) then return end
if not probe("374(0,buf,0x100,0)", uint64(0), uint64(buf), uint64(0x100), uint64(0)) then return end
if not probe("374(path,buf,0,0)", path, uint64(buf), uint64(0), uint64(0)) then return end

print("[E] the shape that died in 944a")
if not probe("374(path,buf,0x100,0)", path, uint64(buf), uint64(0x100), uint64(0)) then return end

print("")
print("[Z] survived every shape - 374 is not unconditionally fatal")
print("=== PROBE 945a COMPLETE ===")
