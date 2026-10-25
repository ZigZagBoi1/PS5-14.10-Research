-- CRASH_CLASS: LOW
-- PROBE 528q: Minimal kernel scan — one page per MiB
--
-- Previous probes timed out scanning too much data.
-- This probe reads ONE qword per MiB across 0-4GB = 4096 reads total.
-- If a MiB starts with a kernel pointer or ELF magic, we log it.
-- Then we can focus deeper probes on those regions.

print("=== PROBE 528q: MINIMAL KERNEL SCAN ===")
print("")

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
print("dmem0 fd=" .. fd)

local sc_477 = mk(477)
local sc_73 = mk(73)
local PAGE = 0x4000

-- Map a BIG window at each offset, read one qword, unmap
-- Actually: map 1 page at each MiB offset. 4096 mmap+read+munmap cycles.
-- Even faster: map 256 MiB at once, read at MiB strides, unmap.
-- 256M / 1M = 256 reads. 4 such windows for 0-1GB.

local MIB = 0x100000
local WINDOW = 0x10000000  -- 256 MiB
local hits = {}

for win_base = 0, 0xFFFFFFFF, WINDOW do
    local chi = math.floor(win_base / 0x100000000)
    local clo = win_base % 0x100000000
    local phys = uint64(string.format("0x%X%08X", chi, clo))

    local ok_m, rv_m = pcall(function()
        return sc_477(uint64(0), uint64(WINDOW), uint64(1), uint64(1), uint64(fd), phys)
    end)

    if ok_m and rv_m then
        local rh, rl = get_hi_lo(rv_m)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh == 0xFFFFFFFF then
            print(string.format("win 0x%X: FAIL", win_base))
        else
            local va_base = N(rv_m)
            -- Read first qword of every MiB in this window
            for mib_off = 0, WINDOW - MIB, MIB do
                local v = rq(va_base + mib_off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh < 0 then vh = vh + 0x100000000 end
                    if vl < 0 then vl = vl + 0x100000000 end
                    local phys_addr = win_base + mib_off
                    -- Kernel pointer
                    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                        table.insert(hits, {phys_addr, vh, vl, "KPTR"})
                        print(string.format("  0x%X: 0x%08X%08X KPTR", phys_addr, vh, vl))
                    end
                    -- ELF
                    local d = rd(va_base + mib_off)
                    if d then
                        if d < 0 then d = d + 0x100000000 end
                        if d == 0x464C457F then
                            table.insert(hits, {phys_addr, 0, d, "ELF"})
                            print(string.format("  0x%X: ELF MAGIC!", phys_addr))
                        end
                    end
                end
            end
            pcall(function() sc_73(rv_m, uint64(WINDOW)) end)
        end
    else
        print(string.format("win 0x%X: CRASH", win_base))
        break
    end
end

print("")
print("hits=" .. #hits)
for _, h in ipairs(hits) do
    print(string.format("  phys 0x%X: %s 0x%08X%08X", h[1], h[4], h[2], h[3]))
end
print("=== 528q DONE ===")
