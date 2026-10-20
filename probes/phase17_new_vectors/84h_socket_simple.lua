-- CRASH_CLASS: LOW
-- PROBE 84h: Create IPv6 socket with correct calling convention
-- syscall objects use __call from ropchain.lua which writes args via resolve_value
-- Try different arg formats: plain numbers, uint64, and via make_syscall

print("=== PROBE 84h: SOCKET SIMPLE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

print("pid=" .. tostring(syscall.getpid()))

-- Test 1: socket via the syscall table directly
print("")
print("--- SOCKET DIRECT ---")
local ok1, ret1 = pcall(function()
    return syscall.socket(28, 2, 17)
end)
print("ok=" .. tostring(ok1))
if ok1 then print("ret=" .. tostring(ret1) .. " fd=" .. to_num(ret1)) end
if not ok1 then print("err=" .. tostring(ret1)) end

-- Test 2: make_syscall version
print("")
print("--- MAKE_SYSCALL ---")
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local ok2, ret2 = pcall(function()
    return make_syscall(97)(28, 2, 17)
end)
print("ok=" .. tostring(ok2))
if ok2 then print("ret=" .. tostring(ret2) .. " fd=" .. to_num(ret2)) end
if not ok2 then print("err=" .. tostring(ret2)) end

-- Close any fds we opened
if ok1 and to_num(ret1) > 0 then
    pcall(function() syscall.close(to_num(ret1)) end)
end
if ok2 and to_num(ret2) > 0 then
    pcall(function() syscall.close(to_num(ret2)) end)
end

-- Test 3: pipe
print("")
print("--- PIPE ---")
local pipebuf = memory.alloc(8)
memory.write_dword(pipebuf, 0)
memory.write_dword(pipebuf + 4, 0)
local ok3, ret3 = pcall(function()
    return syscall.pipe(pipebuf)
end)
print("pipe ok=" .. tostring(ok3))
if ok3 then
    print("ret=" .. tostring(ret3))
    print("rd=" .. to_num(memory.read_dword(pipebuf)))
    print("wr=" .. to_num(memory.read_dword(pipebuf + 4)))
end
if not ok3 then print("err=" .. tostring(ret3)) end

-- Test 4: mmap
print("")
print("--- MMAP ---")
local ok4, ret4 = pcall(function()
    return syscall.mmap(0, 0x4000, 3, 0x1002, -1, 0)
end)
print("mmap ok=" .. tostring(ok4))
if ok4 then print("ret=" .. tostring(ret4)) end
if not ok4 then print("err=" .. tostring(ret4)) end

print("=== PROBE 84h COMPLETE ===")
