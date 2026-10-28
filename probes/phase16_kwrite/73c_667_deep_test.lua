-- CRASH_CLASS: HIGH
-- PROBE 73c: Syscall 667 deep characterization with real AIO IDs
--
-- 667 is the LEAST tested AIO family member. It returned -1 for six zeros
-- in the presence sweep, but was never tested with valid AIO request IDs.
-- Every other AIO readback (662/663/664/666) returns only a 4-byte status
-- dword. 667 might be different — it could return raw object data.
--
-- 665/668 are DEAD (kill on all args). 667 is tested with pcall for safety.

print("=== PROBE 73c: SYSCALL 667 DEEP TEST ===")
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
local function is_alive()
    local ok = pcall(function() mk(20)() end)
    return ok
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

local sc669 = mk(669)
local sc662 = mk(662)
local sc664 = mk(664)
local sc666 = mk(666)
local sc667 = mk(667)
local data_buf = memory.alloc(0x100)

local function submit_one()
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
    return id
end

local function fill_scan(buf, size)
    for i = 0, size - 1 do wb(N(buf) + i, 0xCC) end
end
local function scan_mods(buf, size)
    local mods = {}
    for i = 0, size - 1 do
        local b = rb(N(buf) + i)
        if b and b ~= 0xCC then mods[#mods + 1] = {off = i, val = b} end
    end
    return mods
end

-- Submit 8 AIO requests
print("")
print("[A] Submitting 8 AIO requests")
local ids = {}
for i = 1, 8 do
    local id = submit_one()
    if id and id > 0 then
        pcall(function() sc664(uint64(id)) end)
        ids[#ids + 1] = id
    end
end
print("  submitted+polled: " .. #ids)
for i = 1, math.min(4, #ids) do
    print(string.format("  id[%d] = 0x%X", i, ids[i]))
end

if #ids < 4 then print("ERROR: too few IDs"); return end

-- Verify 666 works as baseline
print("")
print("[B] 666 baseline (known-good)")
do
    local buf = memory.alloc(64)
    fill_scan(buf, 64)
    local ok, ret = pcall(function() return sc666(uint64(ids[1]), uint64(1), buf, uint64(0), uint64(0), uint64(0)) end)
    local mods = scan_mods(buf, 64)
    print(string.format("  666 ret=%s mods=%d", ok and tostring(N(ret)) or "FAIL", #mods))
    for _, m in ipairs(mods) do
        print(string.format("    +%02X = %02X", m.off, m.val))
    end
end

-- Test 667 with the SAME argument layout as 666
print("")
print("[C] 667 with 666-style args: 667(id, 1, buf, 0, 0, 0)")
do
    local buf = memory.alloc(256)
    fill_scan(buf, 256)
    local ok, ret = pcall(function() return sc667(uint64(ids[1]), uint64(1), buf, uint64(0), uint64(0), uint64(0)) end)
    print(string.format("  ret=%s alive=%s", ok and tostring(N(ret)) or "PCALL_FAIL", tostring(is_alive())))
    if ok then
        local mods = scan_mods(buf, 256)
        print(string.format("  mods=%d", #mods))
        for _, m in ipairs(mods) do
            print(string.format("    +%02X = %02X", m.off, m.val))
        end
        -- Full qword dump of first 64 bytes
        print("  qword dump:")
        for off = 0, 56, 8 do
            local q = rq(N(buf) + off)
            if q then
                local h, l = get_hi_lo(q)
                if h ~= 0xCCCCCCCC or l ~= 0xCCCCCCCC then
                    local tag = ""
                    if h >= 0xFFFF8000 then tag = " *** KERNEL ***" end
                    print(string.format("    +%02X: %s%s", off, fmt(q), tag))
                end
            end
        end
    end
    if not is_alive() then print("  KILLED by 667"); return end
end

-- Test 667 with 662-style args (multi-ID)
print("")
print("[D] 667 with 662-style args: 667(id_arr, count, buf, 0, 0, 0)")
do
    local id_arr = memory.alloc(16)
    for i = 1, 4 do wd(N(id_arr) + (i-1)*4, ids[i]) end
    local buf = memory.alloc(256)
    fill_scan(buf, 256)
    local ok, ret = pcall(function() return sc667(id_arr, uint64(4), buf, uint64(0), uint64(0), uint64(0)) end)
    print(string.format("  ret=%s alive=%s", ok and tostring(N(ret)) or "PCALL_FAIL", tostring(is_alive())))
    if ok then
        local mods = scan_mods(buf, 256)
        print(string.format("  mods=%d", #mods))
        for _, m in ipairs(mods) do
            print(string.format("    +%02X = %02X", m.off, m.val))
        end
    end
    if not is_alive() then print("  KILLED by 667"); return end
end

-- Test 667 alternative arg layouts
print("")
print("[E] 667 alternative layouts")
local layouts = {
    {"667(0,id,buf,...)",  function(id,b) return sc667(uint64(0), uint64(id), b, uint64(0), uint64(0), uint64(0)) end},
    {"667(id,buf,1,...)",  function(id,b) return sc667(uint64(id), b, uint64(1), uint64(0), uint64(0), uint64(0)) end},
    {"667(id,0,0,buf,...)",function(id,b) return sc667(uint64(id), uint64(0), uint64(0), b, uint64(0), uint64(0)) end},
    {"667(id,1,0,buf,...)",function(id,b) return sc667(uint64(id), uint64(1), uint64(0), b, uint64(0), uint64(0)) end},
    {"667(buf,1,id,...)",  function(id,b) return sc667(b, uint64(1), uint64(id), uint64(0), uint64(0), uint64(0)) end},
}
local test_idx = 2
for _, lay in ipairs(layouts) do
    if test_idx > #ids then break end
    if not is_alive() then print("  DEAD"); break end
    local buf = memory.alloc(128)
    fill_scan(buf, 128)
    local ok, ret = pcall(function() return lay[2](ids[test_idx], buf) end)
    local mods = ok and scan_mods(buf, 128) or {}
    print(string.format("  %s: ret=%s mods=%d alive=%s",
        lay[1], ok and tostring(N(ret)) or "FAIL", #mods, tostring(is_alive())))
    if #mods > 0 then
        for _, m in ipairs(mods) do
            print(string.format("    +%02X = %02X", m.off, m.val))
        end
    end
    test_idx = test_idx + 1
end

-- Test 667 with arg4 sweep (like 663's mode parameter)
print("")
print("[F] 667 with arg4 sweep")
if is_alive() and #ids >= 5 then
    for _, arg4 in ipairs({0, 1, 2, 3, 4, 8, 0x10, 0x100}) do
        if not is_alive() then break end
        local buf = memory.alloc(64)
        fill_scan(buf, 64)
        local ok, ret = pcall(function() return sc667(uint64(ids[5]), uint64(1), buf, uint64(arg4), uint64(0), uint64(0)) end)
        local mods = ok and scan_mods(buf, 64) or {}
        print(string.format("  arg4=0x%X: ret=%s mods=%d",
            arg4, ok and tostring(N(ret)) or "FAIL", #mods))
    end
end

-- Test 667 on different AIO states
print("")
print("[G] 667 on different AIO states")
if is_alive() then
    -- Unpolled complete
    local id_unpolled = submit_one()
    if id_unpolled and id_unpolled > 0 then
        local buf = memory.alloc(64)
        fill_scan(buf, 64)
        local ok, ret = pcall(function() return sc667(uint64(id_unpolled), uint64(1), buf, uint64(0), uint64(0), uint64(0)) end)
        local mods = ok and scan_mods(buf, 64) or {}
        print(string.format("  UNPOLLED id=0x%X: ret=%s mods=%d",
            id_unpolled, ok and tostring(N(ret)) or "FAIL", #mods))
        if #mods > 0 then
            for _, m in ipairs(mods) do print(string.format("    +%02X=%02X", m.off, m.val)) end
        end
        -- Clean up
        pcall(function() sc664(uint64(id_unpolled)) end)
        local db = memory.alloc(4); local ib2 = memory.alloc(4)
        wd(N(ib2), id_unpolled)
        pcall(function() sc662(ib2, uint64(1), db, uint64(0), uint64(0), uint64(0)) end)
    end

    -- Deleted ID
    if is_alive() and #ids >= 6 then
        local del_id = ids[6]
        local db = memory.alloc(4); local ib2 = memory.alloc(4)
        wd(N(ib2), del_id)
        pcall(function() sc662(ib2, uint64(1), db, uint64(0), uint64(0), uint64(0)) end)

        local buf = memory.alloc(64)
        fill_scan(buf, 64)
        local ok, ret = pcall(function() return sc667(uint64(del_id), uint64(1), buf, uint64(0), uint64(0), uint64(0)) end)
        local mods = ok and scan_mods(buf, 64) or {}
        print(string.format("  DELETED id=0x%X: ret=%s mods=%d",
            del_id, ok and tostring(N(ret)) or "FAIL", #mods))
        if #mods > 0 then
            for _, m in ipairs(mods) do print(string.format("    +%02X=%02X", m.off, m.val)) end
        end
    end
end

-- Cleanup
print("")
print("[H] Cleanup")
for _, id in ipairs(ids) do
    local db = memory.alloc(4); local ib2 = memory.alloc(4)
    wd(N(ib2), id)
    pcall(function() sc662(ib2, uint64(1), db, uint64(0), uint64(0), uint64(0)) end)
end

print("")
if is_alive() then
    print("alive=YES")
else
    print("alive=NO")
end
print("=== PROBE 73c COMPLETE ===")
