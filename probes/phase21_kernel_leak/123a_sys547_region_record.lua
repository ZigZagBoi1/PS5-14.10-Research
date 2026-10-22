-- Isolated version check for the 13.60 sys_547 two-argument ABI.
-- Reads only the current process's allocated user address.
local function sc(n)
    local t = {}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local function show(v)
    if type(v)=="table" and v.h then
        return string.format("0x%08x%08x", v.h, v.l)
    end
    return tostring(v)
end
local getpid=sc(20)
local query=sc(547)
local region=memory.alloc(0x100)
local out=memory.alloc(0x40)
for i=0,0x38,8 do memory.write_qword(out+i,uint64(0x51515151)) end
print("123a begin pid="..show(getpid()).." region="..show(region))
local ok,ret=pcall(function() return query(uint64(region),uint64(out)) end)
print("123a query ok="..tostring(ok).." ret="..show(ret))
for i=0,0x18,8 do
    print(string.format("123a out+%02x=%s",i,show(memory.read_qword(out+i))))
end
print("123a canary pid="..show(getpid()))
print("123a complete")
