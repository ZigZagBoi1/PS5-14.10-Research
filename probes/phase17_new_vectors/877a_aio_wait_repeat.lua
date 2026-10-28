-- CRASH_CLASS: HIGH
-- PROBE 877a: repeat aio_multi_wait (663) on a completed object from the Lua thread.
-- 876a died only when a raw child looped 663; a single call was harmless.  This
-- removes the thread entirely: if a plain Lua loop dies as well, the handler
-- itself is at fault and no threading machinery is involved.
print("=== PROBE 877a: repeated 663 from the Lua thread ===")
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
local D=mmap(page); local ids=mmap(page); local st=mmap(page); local out=mmap(page)
local bufp=mmap(page); local res=mmap(page)
-- fd = -1: the object completes immediately (state 3), no socketpair needed
wq(D+0x00,uint64(0)); wq(D+0x08,uint64(0x1000)); wq(D+0x10,uint64(bufp)); wq(D+0x18,uint64(res))
wd(D+0x20,0xFFFFFFFF); wd(D+0x24,0)
local okc,rvc=pcall(function() return mk(669)(uint64(0x1001),uint64(D),uint64(1),uint64(1),uint64(out)) end)
local id=rd(out) or 0
wd(ids,id); pcall(function() mk(664)(uint64(ids),uint64(1),uint64(st)) end)
print(string.format("[A] create=%s rv=%s id=%08X state=%08X", tostring(okc), tostring(rvc), id, rd(st) or 0))
if id==0 then return end
local ts=memory.alloc(16); wq(ts,0); wq(ts+8,0)
local sc663=mk(663); local sc555=mk(555)
for i=1,200000 do
    wd(ids,id)
    local ok,rv=pcall(function() return sc663(uint64(ids),uint64(1),uint64(st),uint64(0)) end)
    if not ok then print(string.format("[B] pcall failed at i=%d", i)) break end
    if i%2000==0 then
        wd(ids,id); pcall(function() mk(664)(uint64(ids),uint64(1),uint64(st)) end)
        print(string.format("[C] i=%d rv=%s status=%08X poll=%08X", i, tostring(rv), rd(st) or 0, rd(st) or 0))
    end
    if i==200000 then print(string.format("[D] survived 200000 waits, status=%08X", rd(st) or 0)) end
end
print("[Z] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
