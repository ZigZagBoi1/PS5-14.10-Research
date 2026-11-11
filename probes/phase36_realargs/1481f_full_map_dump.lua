-- CRASH_CLASS: LOW -- read-only enumeration. 674 writes only into our own buffer.
-- PROBE 1481f: the complete 674 map with names, protections and first bytes.
--
-- 548 op 2 can change the protection of mappings this process did not create (1480c moved 19
-- device windows from prot 0x33 to 3, and 1481b proved stores then land). Which mappings exist is
-- therefore now an actionable question rather than a survey: every one of them is a candidate for
-- the same treatment, and the ones with content are where a device register file or a driver table
-- would be.
--
-- 1481c only looked at eleven names guessed in advance. This dumps every record so the next probe
-- can be built from the real map: address, size, protection, flags, name, and the first 16 bytes
-- of anything already readable.
--
-- -- prior art:
--   results/phase36_realargs/1481c_gpu_region_content_20261109_201653.txt (11 named windows)
--   results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt (19 moved to prot 3)
--   results/55e_*.txt / 55f_*.txt (an earlier 317-region map, before these moves)

print("=== PROBE 1481f: FULL 674 MAP ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sc674 = mk(674)
local cnt = memory.alloc(0x10)

-- Enough for 512 records of 72 bytes.
local CAP = 512
local buf = memory.alloc(CAP * 72 + 0x1000)
for i = 0, CAP * 72, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
pcall(function() memory.write_dword(cnt, uint64(0)) end)
local okc, c = pcall(function()
    return N(sc674(uint64(buf), uint64(72), uint64(CAP), uint64(cnt), uint64(0x40000000)))
end)
local nrec = 0
pcall(function() nrec = N(memory.read_dword(cnt)) end)
print(string.format("[0] 674 rv=%s records=%d", tostring(okc and c or "EXC"), nrec))
if not okc or c ~= 0 or nrec <= 0 then
    print("=== PROBE 1481f INCOMPLETE ===")
    return
end
if nrec > CAP then nrec = CAP end

local function u64at(b, off)
    local lo, hi = 0, 0
    pcall(function() lo = N(memory.read_dword(b + off)) end)
    pcall(function() hi = N(memory.read_dword(b + off + 4)) end)
    return lo + hi * 4294967296
end

local readable, other = 0, 0
for i = 0, nrec - 1 do
    local b = buf + i * 72
    local s = u64at(b, 0x00)
    local e = u64at(b, 0x08)
    local pr = 0
    local fl = 0
    pcall(function() pr = N(memory.read_dword(b + 0x18)) end)
    pcall(function() fl = N(memory.read_dword(b + 0x1C)) end)
    local name = ""
    for k = 0, 31 do
        local ch = 0
        pcall(function() ch = N(memory.read_byte(b + 0x21 + k)) end)
        if ch == 0 or ch < 32 or ch >= 127 then break end
        name = name .. string.char(ch)
    end
    local head = ""
    if pr == 3 or pr == 5 or pr == 1 then
        readable = readable + 1
        for k = 0, 12, 4 do
            local v = nil
            pcall(function() v = N(memory.read_dword(s + k)) end)
            head = head .. (v and string.format("%08X ", v) or "???????? ")
        end
    else
        other = other + 1
        head = "(prot 0x" .. string.format("%X", pr) .. ", not read)"
    end
    print(string.format("%3d 0x%-11X-0x%-11X sz=0x%-8X prot=0x%-3X fl=0x%-4X %-24s %s",
        i, s, e, e - s, pr, fl, name:sub(1, 24), head))
end

print("")
print(string.format("[A] %d readable, %d not readable of %d", readable, other, nrec))
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1481f COMPLETE ===")
