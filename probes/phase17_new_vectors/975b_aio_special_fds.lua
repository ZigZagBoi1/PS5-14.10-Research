-- CRASH_CLASS: HIGH
-- PROBE 975b: the two descriptors aio submit rejected (10 and 14) probed one at a time
print("=== PROBE 975b: AIO SPECIAL FDS 10 / 14 ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local pid=to_num(mk(20)())
print(string.format("[A] pid=%u", pid))
local reqs=memory.alloc(0x28) local ids=memory.alloc(8) local st=memory.alloc(8) local err=memory.alloc(8)
local buf=memory.alloc(0x200) local ba=addr_of(buf)

local function attempt(fd, tag)
    for i=0,0x1FC,4 do wd(buf+i,0) end
    for i=0,0x24,4 do wd(reqs+i,0) end
    wd(reqs+0x08,0x80)
    wd(reqs+0x10, ba % 4294967296) wd(reqs+0x14, math.floor(ba/4294967296))
    wd(reqs+0x20, fd)
    wd(ids,0)
    local ok, rv = pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(1),uint64(3),uint64(ids)) end)
    if not ok then print(string.format("  [%s fd=%d] PCALL-FAIL", tag, fd)) return end
    local h,l = hi_lo(rv)
    print(string.format("  [%s fd=%d] submit=0x%08X_%08X id=0x%08X", tag, fd, h, l, rd(ids)))
    local id=rd(ids)
    if id ~= 0 then
        for t=0,20 do
            pcall(function() return mk(664)(uint64(ids),uint64(1),uint64(st)) end)
            if rd(st)==3 then break end
        end
        print(string.format("    state=%d", rd(st)))
        local nz=0 first=0
        for i=0,0x7C,4 do if rd(buf+i)~=0 then nz=nz+1 if first==0 then first=i end end end
        print(string.format("    buf non-zero dwords=%d first-offset=%d", nz, first))
        local o=memory.alloc(8) wd(o,id)
        pcall(function() return mk(662)(uint64(o),uint64(1),uint64(err)) end)
        print(string.format("    delete err=0x%08X", rd(err)))
    end
end

for _,fd in ipairs({10, 14, 3, 22}) do
    attempt(fd, "fd")
end
print("[Z] alive=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
