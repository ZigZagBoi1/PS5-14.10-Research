-- CRASH_CLASS: MODERATE
-- PROBE 1341b: VM object operations and page-table modifiers, ordered re-run
--
-- prior art:
--   probes/phase23_cve_2026/524a_vm_ops_deep.lua - the probe the dead end cites;
--       no capture of it exists (the only file named 524a is a different AIO
--       probe that ends "=== PROBE 524a INCOMPLETE ===")
--   docs/DEAD_ENDS.md  "sys 653/654/655/660/667/645/648/658/647 all return -1.
--       No new VM primitives."
--   13.60 contracts: 653 (narg=1) page-table attribute modifier, 654 (narg=5)
--       validated 64 KiB VM range op, 655 (narg=3) range reset companion,
--       660 dynlib info v2 (module_handle, slot_padding, info_inout),
--       667 process/thread enumeration, 645 (narg=0), 648 (narg=1 user ptr),
--       658 descriptor-backed synchronisation, 647 ORBI metadata
--   docs/sysent-names-13.60.csv (all nine names resolve, none is nosys)
--
-- The nine calls are ordered least to most dangerous so that a death is
-- attributable: every call prints a "CALL" line first, and only 653 (the
-- page-table modifier) can take the process down after the earlier sections
-- have already reported.

print("=== PROBE 1341b: VM OPS + PAGE TABLE MODIFIERS, ORDERED ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function parts(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    local n = N(v)
    if n < 0 then return 4294967295, 4294967295 end
    return math.floor(n / 4294967296) % 4294967296, n % 4294967296
end
local function hx(v)
    local h, l = parts(v)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end
local function s64(v)
    local h, l = parts(v)
    if h >= 2147483648 then return l + (h - 4294967296) * 4294967296 end
    return h * 4294967296 + l
end

-- count dwords that look like kernel pointers
local function kptr_scan(addr, sz)
    local hits = 0
    for off = 0, sz - 8, 4 do
        local hi = rd(addr + off + 4)
        if hi and hi >= 0xFFFF8000 then hits = hits + 1 end
    end
    return hits
end
local function dump_nonzero(addr, sz, label)
    local nz = 0
    local first = -1
    for off = 0, sz - 4, 4 do
        local v = rd(addr + off)
        if v and v ~= 0 then
            nz = nz + 1
            if first < 0 then first = off end
        end
    end
    print(string.format("  %s: nonzero=%d first=%s", label, nz,
        first >= 0 and string.format("+0x%X", first) or "-"))
    if first >= 0 then
        for off = first, math.min(first + 0x30, sz - 4), 4 do
            local v = rd(addr + off)
            if v and v ~= 0 then
                print(string.format("    +0x%03X: %08X", off, v))
            end
        end
    end
    return nz
end

local function call1(tag, f, ...)
    print("  CALL " .. tag)
    local ok, rv = pcall(f, ...)
    if ok then
        print(string.format("  %-26s ret=%-5d %s", tag, s64(rv), hx(rv)))
    else
        print(string.format("  %-26s RAISED", tag))
    end
    return ok, rv
end

local pid = 0
pcall(function() pid = N(mk(20)()) end)
print("pid=" .. pid)

local buf = memory.alloc(0x2000)
local out = memory.alloc(0x40)
local info = memory.alloc(0x400)
zero(buf, 0x2000)

-- 593 for the eboot text base, 477 for a GPU mapping to aim 653 at
local eb = 0
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local elo, ehi = rd(N(info) + 0x108), rd(N(info) + 0x10C)
if elo and ehi then eb = ehi * 4294967296 + elo end
print("eboot=" .. string.format("0x%X", eb))

local gpu = 0
local okg, rv = pcall(function()
    return mk(477)(uint64(0), uint64(4 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if okg then gpu = s64(rv) end
print("gpu=" .. string.format("0x%X", gpu))
print("")

-- ---------------------------------------------------------------
print("[A] 645 (narg=0)")
local sc645 = mk(645)
call1("645()", sc645)
print("")

-- ---------------------------------------------------------------
print("[B] 648 (narg=1, user pointer)")
local sc648 = mk(648)
for _, sz in ipairs({ 0x40, 0x100, 0x400 }) do
    zero(buf, 0x1000)
    local ok = call1(string.format("648(buf %X)", sz), sc648, uint64(N(buf)))
    if ok then
        dump_nonzero(buf, sz, "648 out")
    end
end
print("")

-- ---------------------------------------------------------------
print("[C] 658 (descriptor-backed synchronisation)")
local sc658 = mk(658)
local sock = -1
local oks, rvs = pcall(function() return mk(97)(uint64(2), uint64(2), uint64(0)) end)
if oks then sock = s64(rvs) end
print("  udp socket fd=" .. sock)
for _, fd in ipairs({ sock, 0, 1 }) do
    for _, pad in ipairs({ 0, 8, 0x40 }) do
        call1(string.format("658(fd=%d,pad=%d)", fd, pad), sc658,
            uint64(fd), uint64(pad))
    end
end
if sock >= 0 then pcall(function() mk(6)(uint64(sock)) end) end
print("")

-- ---------------------------------------------------------------
print("[D] 647 (ORBI metadata)")
local sc647 = mk(647)
zero(buf, 0x200)
local ok647 = call1("647(&buf)", sc647, uint64(N(buf)))
if ok647 then
    dump_nonzero(buf, 0x200, "647 out")
    print("  kptr-shaped dwords: " .. kptr_scan(buf, 0x200))
end
call1("647(0)", sc647, uint64(0))
print("")

-- ---------------------------------------------------------------
print("[E] 667 (process/thread enumeration, count-only)")
local sc667 = mk(667)
zero(out, 0x40)
call1("667(0,0,&out)", sc667, uint64(0), uint64(0), uint64(N(out)))
print(string.format("  out[0]=%s out[1]=%s",
    hx(rd(N(out)) or 0), hx(rd(N(out) + 4) or 0)))
zero(buf, 0x400)
local ok667 = call1(string.format("667(pid=%d,&buf)", pid), sc667,
    uint64(pid), uint64(N(buf)), uint64(0x400))
if ok667 then
    dump_nonzero(buf, 0x400, "667 out")
    print("  kptr-shaped dwords: " .. kptr_scan(buf, 0x400))
end
print("")

-- ---------------------------------------------------------------
print("[F] 660 (dynlib info v2: handle, slot_padding, info_inout)")
local sc660 = mk(660)
for _, h in ipairs({ 0, 2 }) do
    for _, sz in ipairs({ 0x160, 0x400 }) do
        zero(info, 0x400)
        wq(info, uint64(sz))
        local ok = call1(string.format("660(h=%d,sz=%X)", h, sz), sc660,
            uint64(h), uint64(0), uint64(N(info)))
        if ok then
            dump_nonzero(info, sz, "660 out")
            print("  kptr-shaped dwords: " .. kptr_scan(info, sz))
        end
    end
end
print("")

-- ---------------------------------------------------------------
print("[G] 654 (validated 64 KiB VM range)")
local sc654 = mk(654)
local addrs = { 0, gpu, eb, N(buf) }
local pats = {
    { 0, 0, 0, 0, 0 },
    { 1, 0x4000, 0x3, 0, 0 },
    { 1, 0x4000, 0x33, 0, 0 },
}
for _, a in ipairs(addrs) do
    for _, p in ipairs(pats) do
        zero(buf, 0x400)
        call1(string.format("654(a=%X,sz=%X,prot=%X)", a, p[2], p[3]), sc654,
            uint64(a), uint64(p[2]), uint64(p[3]), uint64(p[4]), uint64(N(buf)))
    end
end
print("")

-- ---------------------------------------------------------------
print("[H] 655 (range reset companion)")
local sc655 = mk(655)
for _, a in ipairs(addrs) do
    for _, prot in ipairs({ 0, 0x3, 0x33 }) do
        call1(string.format("655(a=%X,prot=%X)", a, prot), sc655,
            uint64(a), uint64(0x4000), uint64(prot))
    end
end
print("")

-- ---------------------------------------------------------------
-- 653 last: a page-table attribute modifier is the one call that can also
-- invalidate the page the probe is running from.
print("[I] 653 (page-table attribute modifier)")
local sc653 = mk(653)
for _, a in ipairs(addrs) do
    call1(string.format("653(a=%X)", a), sc653, uint64(a))
end
for _, at in ipairs({ 0x1, 0x3, 0x5, 0x7, 0x33 }) do
    call1(string.format("653(gpu,%X)", at), sc653, uint64(gpu), uint64(at))
end
for _, a in ipairs({ gpu, eb }) do
    for _, at in ipairs({ 0x3, 0x7 }) do
        call1(string.format("653(%X,%X)", a, at), sc653, uint64(a), uint64(at))
    end
end
print("")

local pid2 = 0
local okc = pcall(function() pid2 = N(mk(20)()) end)
print(string.format("canary: ok=%s pid=%s (was %d) %s", tostring(okc), tostring(pid2), pid,
    (okc and pid2 == pid) and "OK" or "CHANGED"))
print("")
print("=== PROBE 1341b COMPLETE ===")
