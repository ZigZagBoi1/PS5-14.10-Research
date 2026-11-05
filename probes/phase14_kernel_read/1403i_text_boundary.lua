-- CRASH_CLASS: MODERATE
-- PROBE 1403i: find eboot .text RX boundary
--
-- Probes one dword per 64KB page from 2.5MB upward.
-- Prints each success. When a read kills the process,
-- the last print shows the boundary.

print("=== 1403i: text boundary ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) memory.write_dword(a, v) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local ebn = N(uint64(string.format("0x%X%08X", eb_hi, eb_lo)))
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Also get eboot file size from dynlib_get_info
-- text_size might be at offset +0x110 or similar
-- Let's dump a few offsets to see
print("")
print("=== info struct ===")
for off = 0x100, 0x158, 4 do
    local v = rd(N(info) + off)
    if v and v ~= 0 then
        print(string.format("+0x%03X: 0x%08X (%d)", off, v, v))
    end
end

-- Probe 4KB pages from 2.5MB upward
print("")
print("=== boundary probe (64KB steps) ===")
local last_ok = 0

-- First verify 2.5MB is still readable
local test = rd(ebn + 0x280000)
if not test then
    print("2.5MB already dead!")
    -- Try earlier
    for step = 0x200000, 0x280000, 0x10000 do
        local t2 = rd(ebn + step)
        if t2 then
            print(string.format("+0x%06X: OK (0x%08X)", step, t2))
            last_ok = step
        else
            print(string.format("+0x%06X: FAIL", step))
            break
        end
    end
else
    print("+0x280000: OK")
    last_ok = 0x280000

    -- Probe upward in 64KB steps
    for step = 0x290000, 0x500000, 0x10000 do
        -- Flush output before the read (in case it kills us)
        io.flush()
        local v = rd(ebn + step)
        if v then
            print(string.format("+0x%06X: OK", step))
            last_ok = step
        else
            print(string.format("+0x%06X: FAIL (pcall caught)", step))
            break
        end
    end
end

print(string.format("last_ok=+0x%06X", last_ok))

-- Refine: within the last 64KB range, probe 4KB pages
if last_ok > 0 then
    print("")
    print("=== refine (4KB steps) ===")
    local refined = last_ok
    for step = last_ok + 0x1000, last_ok + 0x10000, 0x1000 do
        io.flush()
        local v = rd(ebn + step)
        if v then
            refined = step
        else
            break
        end
    end
    print(string.format("refined=+0x%06X", refined))
    print(string.format("text_size=~%d KB (%d MB)", (refined + 0x1000) / 1024, (refined + 0x1000) / 1048576))
end

print("")
print("=== 1403i DONE ===")
