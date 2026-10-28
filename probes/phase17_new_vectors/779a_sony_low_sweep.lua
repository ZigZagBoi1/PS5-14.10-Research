-- CRASH_CLASS: MODERATE
-- PROBE 779a: syscalls 532-560 with real buffers, not zeros
--
-- bg_47 measured 532-560 with six zero arguments: every number answered -1
-- except 548 which answered 0. But 662 also answered -1 for the wrong
-- argument order before the right shape was found, so "-1 with zeros" only
-- proves the zeros did not validate. These are the Sony object calls, and an
-- object call that copies a struct out is exactly where an info leak lives.
-- Each number gets four argument shapes against a zeroed 0x1000 page; the
-- page is scanned for kernel-shaped qwords whenever it is written.
print("=== PROBE 779a: SONY LOW SWEEP ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local page=to_num(memory.alloc(0x2000)); zero(page,0x2000)
local function changed()
    for i=0,63 do
        local v=rd(page+i*4)
        if v and v~=0 then return true end
    end
    return false
end
local function kernscan()
    local n=0
    for i=0,(0x2000/8)-1 do
        local hi=rd(page+i*8+4)
        if hi and hi>=0xFFFF8000 then n=n+1 end
    end
    return n
end
local function dump(tag)
    local s=""
    for i=0,7 do s=s..string.format("%08X ",rd(page+i*4) or 0) end
    print(string.format("    %s %s",tag,s))
end
for n=532,560 do
    local sc=mk(n)
    local shapes={
        {"ptr,size", page, 0x1000, 0, 0},
        {"zero,ptr,size", 0, page, 0x1000, 0},
        {"ptr,size,ptr2", page, 0x1000, page+0x1000, 0x800},
        {"one,ptr,size", 1, page, 0x1000, 0},
    }
    for _,s in ipairs(shapes) do
        zero(page,0x2000)
        local r=call(sc,s[2],s[3],s[4],s[5],0,0)
        if r=="DEAD" then
            print(string.format("[%d] %s -> DEAD",n,s[1]))
            return
        end
        if r~=-1 or changed() then
            local k=kernscan()
            print(string.format("[%d] %-16s ret=%s kern=%d",n,s[1],tostring(r),k))
            dump(s[1])
        end
    end
    print(string.format("[%d] done alive=%s",n,tostring(call(mk(20),0,0,0,0,0,0))))
end
print("=== 779a DONE ===")
