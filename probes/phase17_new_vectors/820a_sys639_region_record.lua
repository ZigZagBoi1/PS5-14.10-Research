-- CRASH_CLASS: LOW
-- PROBE 820a: syscall 639 and 638 with argument 4 as the record pointer
--
-- Context: the argument-shape sweep sent 639(ptr, ptr, ptr, ptr, ptr, ptr) and
-- the two pages it read back changed to 0xF615DB90 and 0x00000E10.  The 13.60
-- body (offset 0x6be800) explains why:
--
--   6BE855  mov  rdx,[rbx]        ; arg1 = address to look up
--   6BE8D7  mov  esi,[rbx+8]      ; arg2 = mode
--   ...     binary search over a sorted table of 16-byte records
--   ...     record = { qword base, dword len, dword extra }
--   6BEA57  mov  r14,[rbx+0x10]   ; arg3 -> 8-byte copyout (offset in region)
--   6BEA8C  mov  r14,[rbx+0x18]   ; arg4 -> 0x10-byte copyout (the record)
--   6BEAC1  mov  rbx,[rbx+0x20]   ; arg5 -> 4-byte copyout (status)
--
-- So the earlier "sys 639 memory region" probe (54f section C) put its buffer
-- in the wrong slot and could only ever see -1.  This probe uses the corrected
-- layout and asks for records for userland addresses, kernel addresses and
-- boundary values.  A record with a high half in 0xFFFF8xxx would be a kernel
-- address leak.  Nothing here dereferences arg1, so the classes are all LOW.

print("=== PROBE 820a: syscall 639 region records ===")
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
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function zero(p,n) for i=0,n-4,4 do wd(p+i,0) end end
local function hex(p,n)
    local t={}
    for i=0,n-4,4 do t[#t+1]=string.format("%08X", rd(p+i) or 0) end
    return table.concat(t," ")
end

local off8 = memory.alloc(0x1000)
local rec  = memory.alloc(0x1000)
local stat = memory.alloc(0x1000)
print(string.format("[A] pid=%d off8=%X rec=%X stat=%X",
    to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)), to_num(off8), to_num(rec), to_num(stat)))

-- one real userland region, so a hit is guaranteed somewhere
local map = memory.alloc(0x20000)
local cntp = memory.alloc(8)
local sc674 = mk(674)
local okc, _ = pcall(function() return sc674(uint64(map), uint64(72), uint64(512), uint64(cntp), uint64(0x40000000), uint64(0)) end)
local regions = okc and rd(cntp) or 0
local uaddr = 0
if regions and regions > 0 then
    uaddr = rd(map) or 0
    if regions > 8 then uaddr = rd(map + 8*72) or uaddr end
end
print(string.format("[B] 674 regions=%s probe_user_addr=%08X", tostring(regions), uaddr))

local sc = mk(639)
local function one(label, addr)
    zero(off8, 0x40); zero(rec, 0x40); zero(stat, 0x40)
    wd(off8, 0xAAAAAAAA); wd(rec, 0xBBBBBBBB); wd(rec+4, 0xCCCCCCCC); wd(rec+8, 0xDDDDDDDD); wd(rec+12, 0xEEEEEEEE); wd(stat, 0x12345678)
    local ok, rv = pcall(function()
        return sc(uint64(addr), uint64(0), uint64(off8), uint64(rec), uint64(stat), uint64(0))
    end)
    if not ok then print(string.format("%s addr=%016X pcall failed", label, addr)); return end
    print(string.format("%s addr=%016X ret=%d rec=[%s] off=[%s] stat=[%s]",
        label, addr, to_num(rv), hex(rec,16), hex(off8,8), hex(stat,4)))
end

one("C user ", uaddr)
one("D heap ", 0x310000000)
one("E zero ", 0)
one("F ktext", 0xFFFFFFFF8A9C0000)
one("G kmid ", 0xFFFFFFFF8B000000)
one("H ktop ", 0xFFFFFFFF8C140000)
one("I phys ", 0x100000000)
one("J max  ", 0xFFFFFFFFFFFFFFFF)

-- 638 is the four-argument sibling; same record slot, second position
local sc638 = mk(638)
zero(rec, 0x40); wd(rec, 0xBBBBBBBB)
local ok8, rv8 = pcall(function()
    return sc638(uint64(0x310000000), uint64(0), uint64(rec), uint64(0x40), uint64(0), uint64(0))
end)
print(string.format("[K] 638(addr,0,rec,0x40) ok=%s ret=%s rec=[%s]",
    tostring(ok8), ok8 and tostring(to_num(rv8)) or "-", hex(rec,16)))
print("[L] survived")
