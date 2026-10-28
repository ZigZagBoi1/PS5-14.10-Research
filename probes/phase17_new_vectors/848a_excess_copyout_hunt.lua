-- CRASH_CLASS: MODERATE
-- PROBE 848a: does any record-returning handler write past the size we declare?
--
-- Every leak sweep so far passed a buffer that was big enough for the full
-- record, so an excess copyout would have landed inside our own buffer and
-- looked like normal output. Here each call gets a buffer at +0x800 of a page
-- with the rest of the page filled with 0xCC, and a DECLARED size of 4 or 8
-- bytes. Anything a handler writes beyond that is visible as non-0xCC bytes,
-- and the excess is scanned for kernel-shaped qwords (0xFFFF8xxx).
--
-- A handler that ignores our size and writes its full record is an info-leak
-- candidate: the excess usually contains stack or heap the caller never asked
-- for. A handler that writes exactly what we asked reports excess=0.

print("=== PROBE 848a: excess copyout hunt ===")
print("")
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
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

-- survive faults where the kernel allows it
pcall(function() mk(416)(uint64(12), uint64(2), uint64(0), uint64(0)) end)
pcall(function() mk(416)(uint64(11), uint64(2), uint64(0), uint64(0)) end)

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

local function fill(a,n,byte)
    pcall(function() for i=0,n-1,4 do memory.write_dword(a+i, byte*0x01010101) end end)
end

local BASE = 0x800
local function newpage()
    local p = mmap(page)
    fill(p, page, 0xCC)
    return p
end

local function scan(p, declared, tag)
    local excess, kern, first = 0, 0, nil
    local shown = {}
    for off = BASE + declared, page - 8, 4 do
        local v = rd(p + off)
        if v and v ~= 0xCCCCCCCC then
            excess = excess + 4
            if not first then first = off end
            if #shown < 8 then shown[#shown+1] = string.format("%X:%08X", off-BASE, v) end
        end
    end
    for off = BASE + declared, page - 8, 8 do
        local v = rq(p + off)
        if v then
            local hi = math.floor(v / 4294967296)
            if hi >= 0xFFFF8000 and hi <= 0xFFFFFFFF then kern = kern + 1 end
        end
    end
    print(string.format("  %-28s declared=%d excess=%d kernel-qwords=%d %s", tag, declared, excess, kern,
        first and ("first=+"..string.format("%X", first-BASE).." ["..table.concat(shown," ").."]") or ""))
end

local B = BASE
local data = mmap(page)

-- 1. 674 region walk: declare room for one record (72 bytes)
local p = newpage(); local cnt = mmap(page)
local ok, rv = pcall(function() return mk(674)(uint64(p+B), uint64(72), uint64(1), uint64(cnt), uint64(0x40000000)) end)
print(string.format("[674] ret=%s regions=%d", tostring(to_num(rv)), rd(cnt) or 0))
scan(p, 72, "674 regions")

-- 2. 587 credential record, declare 8
p = newpage()
ok, rv = pcall(function() return mk(587)(uint64(p+B)) end)
print(string.format("[587] ret=%s", tostring(to_num(rv))))
scan(p, 8, "587 cred")

-- 3. 649 module member, declare 8
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
p = newpage()
ok, rv = pcall(function() return mk(649)(uint64(0), uint64(1), uint64(p+B), uint64(8), uint64(0), uint64(0)) end)
print(string.format("[649] eboot=%X ret=%s", ebase, tostring(to_num(rv))))
scan(p, 8, "649 member1")

-- 4. 572 heap record, declare 8
p = newpage()
ok, rv = pcall(function() return mk(572)(uint64(data), uint64(0x400), uint64(p+B), uint64(8), uint64(0), uint64(0)) end)
print(string.format("[572] ret=%s", tostring(to_num(rv))))
scan(p, 8, "572 heap rec")

-- 5. 626 cmd 6, four dwords, declare 4
p = newpage()
ok, rv = pcall(function() return mk(626)(uint64(6), uint64(0), uint64(0), uint64(p+B), uint64(p+B)) end)
print(string.format("[626] ret=%s", tostring(to_num(rv))))
scan(p, 4, "626 counters")

-- 6. 671 resource classes, declare 4
p = newpage()
ok, rv = pcall(function() return mk(671)(uint64(0xFFFFFFFF), uint64(1), uint64(p+B), uint64(4)) end)
print(string.format("[671] mode1 ret=%s a=%08X b=%08X", tostring(to_num(rv)), rd(p+B) or 0, rd(p+B+4) or 0))
scan(p, 4, "671 mode1")

-- 7. 592 dynlib count, declare 4
p = newpage()
ok, rv = pcall(function() return mk(592)(uint64(p+B), uint64(4), uint64(p+B+0x40)) end)
print(string.format("[592] ret=%s count=%d", tostring(to_num(rv)), rd(p+B+0x40) or 0))
scan(p, 4, "592 count")

-- 8. 593 module info, declare 8 (the full record is 0x160)
p = newpage()
ok, rv = pcall(function() return mk(593)(uint64(0), uint64(p+B)) end)
print(string.format("[593] ret=%s", tostring(to_num(rv))))
scan(p, 8, "593 info")

print("[Z] done")
