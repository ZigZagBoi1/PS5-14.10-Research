-- CRASH_CLASS: MODERATE
-- PROBE 868a: sys 538 stores a user-supplied qword in the object; does anyone follow it?
--
-- 13.60 body 0xbafa80: flags=[uap+8] (mask 0xfffffecc, low 2 bits must not be 3,
-- 0x30 bits must not be 0x30), [uap] = name pointer (copyinstr 0x20), then
-- malloc(0x58) and  [obj+0x00] = [uap+0x10]  <- a user qword stored verbatim,
-- [obj+0x20] mtx_init, [obj+0x28] cv_init, [obj+0x38]=0, [obj+0x40]=&obj+0x38,
-- [obj+0x48]=flags, [obj+0x4c]=0, [obj+0x50]=0/1, [obj+0x54]=pid, then the id
-- comes from 0x3998e0 and the object registers with type 0x110.
--
-- This probe stores a canary page address at [obj] and calls the neighbouring
-- syscalls with that id, watching the page for writes.  A write would mean a
-- handler follows the caller-controlled pointer.
print("=== PROBE 868a: the 538 object's user-supplied first qword ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function make_syscall(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local sc=make_syscall
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
local function mmap()
    local _,a=pcall(function() return sc(477)(U(0),U(0x4000),U(3),U(0x1002),U(0xFFFFFFFF),U(0)) end)
    local v=to_num(a); if v~=0 then zero(v,0x4000) end; return v
end
local can = mmap()
local sum = function() local s=0 for i=0,0x3FF do s=(s+rd(can+i*4))%4294967296 end return s end
for i=0,0x3FF do wd(can+i*4, 0xAAAAAAAA) end
local base = sum()
print(string.format("[A] canary %08X sum=%08X", can, base))
local name = memory.alloc(0x40); wd(name,0x53); wd(name+4,0x38)
local st = memory.alloc(0x40)
local ok, id = pcall(function() return sc(538)(U(to_num(name)),U(0x11),U(can),U(0),U(0),U(0)) end)
local oid = to_num(id)
print(string.format("[B] 538(name,0x11,canary) ok=%s rv=%08X", tostring(ok), oid))
if oid == 0xFFFFFFFF then print("[B] create failed"); return end
local names = {[541]="541",[542]="542",[543]="543",[544]="544",[545]="545",[546]="546",[547]="547",[537]="537",[539]="539",[540]="540"}
for n=537,547 do
    if n ~= 538 then
        local f = make_syscall(n)
        local o1, r1 = pcall(function() return f(U(oid),U(0),U(0),U(0),U(0),U(0)) end)
        local o2, r2 = pcall(function() return f(U(oid),U(1),U(can),U(0),U(0),U(0)) end)
        local d = (sum() - base) % 4294967296
        print(string.format("[C] %s id=%08X r1=%s r2=%s canary-delta=%d", names[n] or tostring(n), oid, tostring(r1), tostring(r2), d))
        if d ~= 0 then print("[C] !! canary changed by syscall " .. n); break end
    end
end
print(string.format("[Z] alive pid=%s", tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)))))
