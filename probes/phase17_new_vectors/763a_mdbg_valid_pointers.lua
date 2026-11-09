-- CRASH_CLASS: HIGH
-- PROBE 763a: mdbg 601 commands 03/04 with pointers that are not NULL
--
-- 601 answers cmd 0x00 with ret=0 and a page whose first dword is 0x100. Commands
-- 0x01 and 0x02 return -1. Commands 0x03 and 0x04 killed the whole game process
-- in the earlier sweep, but that sweep passed a page of zeros, so a handler that
-- dereferences a pointer from the argument block would fault on NULL - which in
-- the kernel is a panic, not a userland signal.
--
-- This fills the argument page with a pointer to a valid mapped page at every
-- qword, so a dereference of any field lands on readable, writable user memory,
-- and adds the pid in a second shape. Each call is preceded by a marker print,
-- so the last line on disk names the call that killed the process.

print("=== PROBE 763a: MDBG 601 WITH VALID POINTERS ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(U(a1), U(a2), U(a3), U(a4), U(a5), U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local pid = call(syscall.pipe, 20,0,0,0,0,0,0)
print("[A] tid="..tostring(pid))

local page = 0x1000
local argp = to_num(memory.alloc(page))
local target = to_num(memory.alloc(page))
local out = to_num(memory.alloc(page))
zero(target, page)
zero(out, page)

local function fill_ptrs()
    zero(argp, page)
    for off=0,page-8,8 do wq(argp+off, uint64(target)) end
end
local function fill_zero()
    zero(argp, page)
end
local function fill_pid()
    zero(argp, page)
    wd(argp, pid); wd(argp+4, pid); wd(argp+8, pid)
    wq(argp+0x10, uint64(target))
end

local function try(tag, cmd, a1, a2)
    print(string.format("[B] %s: 601(%s, %s, 0)", tag, tostring(cmd), tostring(a1)))
    local r = call(mk(601), cmd, a1, a2, 0, 0, 0)
    local head = {}
    for i=0,3 do head[#head+1] = string.format("%08X", rd(out + i*4) or 0) end
    print(string.format("[B] %s -> ret=%s out=%s", tag, tostring(r), table.concat(head, " ")))
    print("[B] alive="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
end

fill_ptrs()
try("03-page-as-arg2", 0x03, argp, out)
fill_pid()
try("03-pid-in-arg2", 0x03, argp, out)
fill_ptrs()
try("03-arg1-page", 0x03, 0, argp)
fill_ptrs()
try("04-page-as-arg2", 0x04, argp, out)
fill_pid()
try("04-pid-in-arg2", 0x04, argp, out)
print("[C] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 763a DONE ===")
