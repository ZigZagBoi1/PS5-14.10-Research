-- CRASH_CLASS: MODERATE
-- PROBE 944a: extattr surface, never probed on 14.10
--
-- Context: docs/REMAINING_CVE_TRIAGE-style sweeps and the probe inventory both
-- note that no extattr_* probe exists anywhere in this repository, and neither
-- does one for SIOCSIF*.  extattr is attractive because it is a filesystem path
-- where the kernel parses a name and a length from userland, on a filesystem we
-- can actually write to (/av_contents/content_tmp was proven writable in 939c,
-- unlike /savedata0).
--
-- This probe only measures the surface: which of 371-378 exist on 14.10, what
-- they return for a valid descriptor and small valid arguments, and whether a
-- name-length or value-length boundary changes the return.  No hostile length is
-- sent - the goal is to learn the argument order and the errno shape first.
--
-- A getpid canary runs after every call, so a lethal number is reported instead
-- of truncating the run silently.

print("=== PROBE 944a: EXTATTR SURFACE ===")
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

-- a file we are allowed to create (939c), then reopen for a descriptor
local path = "/av_contents/content_tmp/extattr_test.bin"
local sc_open, sc_write, sc_close = mk(5), mk(4), mk(6)
local fd = call(function() return sc_open(path, uint64(0x202), uint64(0x1FF)) end)
if fd == nil then
    local ok, err = pcall(function() return sc_open(path, uint64(0x202), uint64(0x1FF)) end)
    print("[0] open raised: " .. tostring(err))
end
print("[0] open(O_RDWR|O_CREAT) = " .. tostring(fd))
if type(fd) ~= "number" or fd < 0 then
    print("[!] cannot create the test file - aborting")
    print("=== PROBE 944a COMPLETE ===")
    return
end
local name = "user.test"
local value = "hello"
print("[0] write = " .. tostring(call(function() return sc_write(uint64(fd), value, uint64(#value)) end)))

local out = memory.alloc(0x100)
local function canary(tag)
    local p = call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
    if p ~= pid then
        print(string.format("[!] canary changed after %s: %s", tag, tostring(p)))
        return false
    end
    return true
end

print("[A] syscall numbers on a valid fd, small arguments")
local shapes = {
    { n = 371, args = { path, name, value, #value, 0 }, label = "set_file(path,name,val,len,0)" },
    { n = 372, args = { path, name, out, 0x100, 0 }, label = "get_file(path,name,buf,len,0)" },
    { n = 373, args = { path, name, 0 }, label = "delete_file(path,name,0)" },
    { n = 374, args = { path, out, 0x100, 0 }, label = "list_file(path,buf,len,0)" },
    { n = 375, args = { fd, name, value, #value, 0 }, label = "set_fd(fd,name,val,len,0)" },
    { n = 376, args = { fd, name, out, 0x100, 0 }, label = "get_fd(fd,name,buf,len,0)" },
    { n = 377, args = { fd, name, 0 }, label = "delete_fd(fd,name,0)" },
    { n = 378, args = { fd, out, 0x100, 0 }, label = "list_fd(fd,buf,len,0)" },
}

for _, s in ipairs(shapes) do
    local sc = mk(s.n)
    local a = s.args
    local ret = call(function() return sc(a[1], a[2], a[3], a[4], a[5]) end)
    local first = nil
    local ok, v = pcall(function() return memory.read_dword(out) end)
    if ok then first = to_num(v) end
    print(string.format("  %-34s ret=%-12s out0=0x%08X", s.label, tostring(ret), first or 0))
    if not canary(s.n) then break end
end

print("[B] name-length boundary on the getter (372), same fd")
for _, len in ipairs({ 0, 1, 8, 9, 31, 32, 255, 256, 0x1000 }) do
    local n = string.rep("a", len)
    local sc = mk(372)
    local ret = call(function() return sc(path, n, uint64(out), uint64(0x100), uint64(0)) end)
    print(string.format("  name_len=%-5d ret=%s", len, tostring(ret)))
    if not canary("372/" .. len) then break end
end

print("[C] value buffer length on the list call (374)")
for _, len in ipairs({ 0, 1, 4, 0x100, 0x1000 }) do
    local sc = mk(374)
    local ret = call(function() return sc(path, uint64(out), uint64(len), uint64(0)) end)
    print(string.format("  buflen=0x%-6X ret=%s", len, tostring(ret)))
    if not canary("374/" .. len) then break end
end

call(function() return sc_close(uint64(fd)) end)
print("")
print("=== PROBE 944a COMPLETE ===")
