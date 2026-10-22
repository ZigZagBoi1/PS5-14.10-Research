-- CRASH_CLASS: LOW
-- PROBE 382a: who in our readable memory points into the GPU aperture
--
-- The graphics driver's mappings are in the process (375a): the command ring
-- SceGnmAcqRb at 0x1148000-0x1328000, TrapCode at 0x0, the driver aperture at
-- 0xE0000000. They cannot be read (376a/380a) and a store into them cannot be
-- confirmed (381a). What can still be read is everything else: if a queue or
-- context structure in our own heap holds the ring base and its producer index,
-- those qwords are visible here even though the ring itself is not.
--
-- This probe walks every readable region the 674 map reports, unpacks it as
-- qwords, and prints the first few values that land inside the aperture or the
-- ring. It reads only memory the map says is readable, and stops a region on the
-- first fault.

print("=== PROBE 382a: GPU APERTURE REFERENCES ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function U(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end

-- region list from 674 (the call shape 375a established)
local STRIDE, MAXR = 72, 512
local map = memory.alloc(STRIDE * MAXR)
local countp = memory.alloc(16)
for i = 0, STRIDE * 4 - 1, 4 do pcall(function() memory.write_dword(map + i, 0) end) end
for i = 0, 12, 4 do pcall(function() memory.write_dword(countp + i, 0) end) end
make_syscall(674)(uint64(map), uint64(STRIDE), uint64(MAXR), uint64(countp), uint64(0x40000000))
local n = to_num(safe_rd(countp))
if n > MAXR then n = MAXR end
print(string.format("[map] regions=%d", n))
if n <= 0 then return end

local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end return 0 end
local function pair(rec) return rd(rec + 4) * 4294967296 + rd(rec) end

local function in_aperture(v)
    return (v >= 0x1148000 and v < 0x1328000) or (v >= 0xE0000000 and v < 0xE0400000)
end

local total_hits = 0
local scanned = 0
for r = 0, n - 1 do
    local rec = map + r * STRIDE
    local start = pair(rec)
    local stop  = pair(rec + 0x08)
    local prot  = rd(rec + 0x18)
    do
        local sh, sl = math.floor(start / 4294967296), start % 4294967296
        local eh, el = math.floor(stop / 4294967296), stop % 4294967296
        local pl = prot
        local readable = (pl == 3 or pl == 5)
        local rname = "r" .. r
        do
            local ln = rd(rec + 0x20) % 256
            if ln > 0 and ln < 64 then
                local ok2, nm = pcall(function() return memory.read_buffer(rec + 0x21, ln) end)
                if ok2 and nm then rname = nm end
            end
        end
        if readable and sh == eh then
            local size = el - sl
            if size > 0 then
                local want = size
                if want > 0x200000 then want = 0x200000 end
                local count = math.floor(want / 8)
                scanned = scanned + 1
                local ok, qs = pcall(function() return memory.read_multiple_qwords(U(sh, sl), count) end)
                if ok and qs then
                    local hits = 0
                    for i, q in ipairs(qs) do
                        local qh, ql = q.h or 0, to_num(q)
                        if qh == 0 and in_aperture(ql) then
                            hits = hits + 1
                            total_hits = total_hits + 1
                            if hits <= 5 then
                                print(string.format("  [hit] %s off=0x%X value=0x%X", rname, (i - 1) * 8, ql))
                            end
                        end
                    end
                    if hits > 5 then
                        print(string.format("  ... %s: %d hit(s) total", rname, hits))
                    end
                else
                    print(string.format("  [skip] region=%d unreadable in practice", r))
                end
            end
        end
    end
end

print("")
print(string.format("scanned %d readable regions, %d qword(s) in the aperture", scanned, total_hits))
print("")
print("=== 382a DONE ===")
