-- CRASH_CLASS: LOW
-- PROBE 72d: How many bytes does 663 actually write to the output buffer?
--
-- 71h/72c only checked 4-byte status (0xDEAD sentinel). If 663 writes 8+
-- bytes, the extra bytes could contain kernel pointers or stale data from
-- the freed R/I/Q objects.
--
-- Tests each AIO readback syscall (663/666/664/662) with a fully
-- sentinel-filled buffer and reports exactly which bytes changed.

print("=== PROBE 72d: AIO OUTPUT SIZE MEASUREMENT ===")
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
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end

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

local data_buf = memory.alloc(0x100)
local result_buf = memory.alloc(0x100)

local function aio_submit()
    local req = memory.alloc(0x28)
    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(16))
    wq(N(req) + 0x10, uint64(N(data_buf)))
    wq(N(req) + 0x18, uint64(N(result_buf)))
    wq(N(req) + 0x20, uint64(fd_zero))
    local oid = memory.alloc(8); wd(N(oid), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(oid)))
    end)
    return rd(N(oid)) or 0
end

local function aio_poll(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0)
    pcall(function() mk(664)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
end

local function fill_sentinel(buf, size)
    for i = 0, size - 1 do wb(N(buf) + i, 0xDE) end
end

local function dump_modified(buf, size, label)
    local modified = 0
    local first_mod = -1
    local last_mod = -1
    local line = ""
    for i = 0, size - 1 do
        local v = rb(N(buf) + i)
        if v ~= 0xDE then
            modified = modified + 1
            if first_mod == -1 then first_mod = i end
            last_mod = i
        end
    end
    print(string.format("  %s: %d/%d bytes modified (first=%d last=%d)",
        label, modified, size, first_mod, last_mod))
    if modified > 0 and modified <= 64 then
        local hex = "    "
        for i = first_mod, last_mod do
            local v = rb(N(buf) + i)
            if v == 0xDE then
                hex = hex .. ".. "
            else
                hex = hex .. string.format("%02X ", v)
            end
            if (i - first_mod + 1) % 16 == 0 and i < last_mod then
                print(hex .. string.format(" +0x%02X", first_mod + (i - first_mod + 1) - 16))
                hex = "    "
            end
        end
        if #hex > 4 then
            print(hex .. string.format(" +0x%02X", first_mod))
        end
    end
    -- Also dump as dwords for easy reading
    if modified > 0 then
        local dwords = ""
        for i = 0, math.min(size - 4, 60), 4 do
            local v = rd(N(buf) + i)
            if v ~= 0xDEDEDEDE then
                dwords = dwords .. string.format(" [+%d]=0x%08X", i, v or 0)
            end
        end
        if #dwords > 0 then
            print("  dwords:" .. dwords)
        end
    end
    return modified, first_mod, last_mod
end

print("")

-- ============================================================
-- [A] 663 output size test
-- ============================================================
print("[A] 663 output size (completed+polled request)")
local id_a = aio_submit()
aio_poll(id_a)
print(string.format("  id=0x%X", id_a))

local out_a = memory.alloc(64)
fill_sentinel(out_a, 64)
local ids_a = memory.alloc(8); wd(N(ids_a), id_a)

pcall(function() mk(663)(uint64(N(ids_a)), uint64(1), uint64(N(out_a))) end)
dump_modified(out_a, 64, "663")

-- Cleanup
local del_a = memory.alloc(8); wd(N(del_a), id_a)
local dst_a = memory.alloc(8)
pcall(function() mk(662)(uint64(N(del_a)), uint64(1), uint64(N(dst_a))) end)
print("")

-- ============================================================
-- [B] 666 output size test
-- ============================================================
print("[B] 666 output size (completed+polled request)")
local id_b = aio_submit()
aio_poll(id_b)
print(string.format("  id=0x%X", id_b))

local out_b = memory.alloc(64)
fill_sentinel(out_b, 64)
local ids_b = memory.alloc(8); wd(N(ids_b), id_b)

pcall(function() mk(666)(uint64(N(ids_b)), uint64(1), uint64(N(out_b))) end)
dump_modified(out_b, 64, "666")

local del_b = memory.alloc(8); wd(N(del_b), id_b)
local dst_b = memory.alloc(8)
pcall(function() mk(662)(uint64(N(del_b)), uint64(1), uint64(N(dst_b))) end)
print("")

-- ============================================================
-- [C] 664 output size test
-- ============================================================
print("[C] 664 output size (completed request)")
local id_c = aio_submit()
print(string.format("  id=0x%X", id_c))

local out_c = memory.alloc(64)
fill_sentinel(out_c, 64)
local ids_c = memory.alloc(8); wd(N(ids_c), id_c)

pcall(function() mk(664)(uint64(N(ids_c)), uint64(1), uint64(N(out_c))) end)
dump_modified(out_c, 64, "664")

local del_c = memory.alloc(8); wd(N(del_c), id_c)
local dst_c = memory.alloc(8)
pcall(function() mk(662)(uint64(N(del_c)), uint64(1), uint64(N(dst_c))) end)
print("")

-- ============================================================
-- [D] 662 output size test
-- ============================================================
print("[D] 662 output size (completed+polled request)")
local id_d = aio_submit()
aio_poll(id_d)
print(string.format("  id=0x%X", id_d))

local out_d = memory.alloc(64)
fill_sentinel(out_d, 64)
local ids_d = memory.alloc(8); wd(N(ids_d), id_d)

pcall(function() mk(662)(uint64(N(ids_d)), uint64(1), uint64(N(out_d))) end)
dump_modified(out_d, 64, "662")
print("")

-- ============================================================
-- [E] Multi-count test: 663 with count=4
-- ============================================================
print("[E] 663 with count=4 (4 completed+polled requests)")
local multi_ids = {}
for i = 1, 4 do
    local mid = aio_submit()
    aio_poll(mid)
    multi_ids[i] = mid
end
print(string.format("  ids: 0x%X 0x%X 0x%X 0x%X",
    multi_ids[1], multi_ids[2], multi_ids[3], multi_ids[4]))

local ids_e = memory.alloc(32)
for i = 0, 3 do wd(N(ids_e) + i * 4, multi_ids[i + 1]) end

local out_e = memory.alloc(256)
fill_sentinel(out_e, 256)

pcall(function() mk(663)(uint64(N(ids_e)), uint64(4), uint64(N(out_e))) end)
dump_modified(out_e, 256, "663x4")

-- Per-entry breakdown
print("  per-entry:")
for i = 0, 3 do
    local v = rd(N(out_e) + i * 4)
    local v2 = rd(N(out_e) + i * 4 + 4)
    print(string.format("    entry[%d]: dword=0x%08X next_dword=0x%08X",
        i, v or 0xDEDEDEDE, v2 or 0xDEDEDEDE))
end

-- Cleanup multi
for i = 1, 4 do
    local di = memory.alloc(8); wd(N(di), multi_ids[i])
    local ds = memory.alloc(8)
    pcall(function() mk(662)(uint64(N(di)), uint64(1), uint64(N(ds))) end)
end
print("")

-- ============================================================
-- [F] 663 on unpolled completed request (different output?)
-- ============================================================
print("[F] 663 on unpolled completed request (/dev/zero)")
local id_f = aio_submit()
-- DON'T poll
print(string.format("  id=0x%X (not polled)", id_f))

local out_f = memory.alloc(64)
fill_sentinel(out_f, 64)
local ids_f = memory.alloc(8); wd(N(ids_f), id_f)

pcall(function() mk(663)(uint64(N(ids_f)), uint64(1), uint64(N(out_f))) end)
dump_modified(out_f, 64, "663_unpolled")

-- Also check: does 666 differ on unpolled?
local out_f2 = memory.alloc(64)
fill_sentinel(out_f2, 64)
local ids_f2 = memory.alloc(8); wd(N(ids_f2), id_f)
pcall(function() mk(666)(uint64(N(ids_f2)), uint64(1), uint64(N(out_f2))) end)
dump_modified(out_f2, 64, "666_unpolled")

aio_poll(id_f)
local del_f = memory.alloc(8); wd(N(del_f), id_f)
local dst_f = memory.alloc(8)
pcall(function() mk(662)(uint64(N(del_f)), uint64(1), uint64(N(dst_f))) end)
print("")

-- ============================================================
-- [G] 667 output size test
-- ============================================================
print("[G] 667 output size (completed+polled request)")
local id_g = aio_submit()
aio_poll(id_g)
print(string.format("  id=0x%X", id_g))

local out_g = memory.alloc(64)
fill_sentinel(out_g, 64)
local ids_g = memory.alloc(8); wd(N(ids_g), id_g)

local ok_g, ret_g = pcall(function()
    return mk(667)(uint64(N(ids_g)), uint64(1), uint64(N(out_g)))
end)
print(string.format("  667 ret: ok=%s val=%s", tostring(ok_g),
    ok_g and tostring(N(ret_g)) or "CRASH"))
dump_modified(out_g, 64, "667")

local del_g = memory.alloc(8); wd(N(del_g), id_g)
local dst_g = memory.alloc(8)
pcall(function() mk(662)(uint64(N(del_g)), uint64(1), uint64(N(dst_g))) end)
print("")

print("alive=YES")
print("=== PROBE 72d COMPLETE ===")
