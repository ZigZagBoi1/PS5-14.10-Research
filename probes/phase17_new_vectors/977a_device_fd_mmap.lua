-- CRASH_CLASS: MODERATE
-- PROBE 977a: mmap and read against the two special descriptors (10 and 14)
--
-- 975c/976a found fd 10 answering EINVAL and fd 14 answering the Sony status
-- 0x803B0004 to every ioctl, and the same two are the only fds aio submit rejects.
-- If either is a device that can be mapped, its pages become readable here.
print("=== PROBE 977a: DEVICE FD MMAP / READ ===")
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

local function mm(fd, flags, prot, tag)
    local ok, rv = pcall(function() return mk(477)(uint64(0),uint64(0x4000),uint64(prot),uint64(flags),uint64(fd),uint64(0)) end)
    if not ok then print(string.format("  [%s fd=%d fl=0x%X] PCALL-FAIL", tag, fd, flags)) return nil end
    local h,l = hi_lo(rv)
    local r = to_num(rv)
    print(string.format("  [%s fd=%d fl=0x%X prot=%d] ret=0x%08X_%08X", tag, fd, flags, prot, h, l))
    if h == 0 and l > 0 and l < 0x80000000 then return l end
    return nil
end

for _,fd in ipairs({10, 14, 3}) do
    local p = mm(fd, 0x1002, 3, "map1002")
    if p then
        print(string.format("    first qwords: %08X %08X %08X %08X", rd(p), rd(p+4), rd(p+8), rd(p+12)))
        pcall(function() return mk(73)(uint64(p),uint64(0x4000)) end)
    end
    p = mm(fd, 0x1001, 3, "map1001")
    if p then
        print(string.format("    first qwords: %08X %08X", rd(p), rd(p+4)))
        pcall(function() return mk(73)(uint64(p),uint64(0x4000)) end)
    end
end

print("[B] read(fd, buf, 0x40)")
local buf=memory.alloc(0x80)
for _,fd in ipairs({10, 14, 18, 19}) do
    for i=0,0x7C,4 do wd(buf+i,0) end
    local ok, rv = pcall(function() return mk(3)(uint64(fd),uint64(buf),uint64(0x40)) end)
    if not ok then print(string.format("  fd=%d PCALL-FAIL", fd))
    else
        local h,l = hi_lo(rv)
        print(string.format("  fd=%d read ret=0x%08X_%08X buf0=%08X", fd, h, l, rd(buf)))
    end
end
print("[Z] alive=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
