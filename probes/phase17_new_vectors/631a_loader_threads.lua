-- CRASH_CLASS: MODERATE
print("=== PROBE 631a: LOADER THREADS ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local pid=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print(string.format("[A] pid=%d",pid))
local sc20=mk(20)
local ok1,t1=pcall(function()
    local c=thread:new(sc20)
    c:run(true)
    local addr=c.chain:get_last_retval_addr()
    c:join()
    return N(memory.read_qword(addr))
end)
print(string.format("[B] one thread getpid -> %s ok=%s",tostring(t1),tostring(ok1)))
local ok2,r1,r2=pcall(function()
    local a=thread:new(mk(20))
    local b=thread:new(mk(20))
    a:run(true)
    b:run(true)
    local aa=a.chain:get_last_retval_addr()
    local bb=b.chain:get_last_retval_addr()
    a:join() b:join()
    return N(memory.read_qword(aa)),N(memory.read_qword(bb))
end)
print(string.format("[C] two threads -> %s %s ok=%s",tostring(r1),tostring(r2),tostring(ok2)))
print(string.format("[D] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("[Z] alive")
