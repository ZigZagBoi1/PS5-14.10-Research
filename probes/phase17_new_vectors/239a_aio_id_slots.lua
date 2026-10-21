-- CRASH_CLASS: MODERATE
-- PROBE 239a: the id slot space of 662/664, and 660 with pointer-shaped handles
--
-- Context: 238a swept the first argument of 548 and 657 over 0..31 and the
-- page address; every call returned -1, so neither handler can be reached with
-- an object this process can name. 237a swept 662/663/664 over eleven id
-- encodings built from the two module handles and slot indices 0..3; every one
-- returned ret=0 with a per-item status of 0x80020003, which reads as "no such
-- id" rather than "bad arguments".
--
-- Two possibilities are left for the id space:
--   [A] the slot index is wider than the four values tried, so sweep 0..255
--       with handle 0x13 and look for any status other than 0x80020003.
--   [B] the handle half is what matters, so sweep handle 0..255 with slot 0.
--   [C] 660's handle may be a pointer rather than an index: try the address of
--       a mapped page, and try the info gate word at +0x00 and +0x10 as well,
--       in case the contract's offset was recovered wrong.
--
-- Nothing here writes to a page the probe did not map, and every call is inside
-- pcall. A kill would be the first evidence that one of these ids is real.

print("=== PROBE 239a: ID SLOT SPACE AND 660 HANDLES ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    if type(val) == "number" then val = uint64(val) end
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(val)
    if val == nil then return "nil" end
    local text = tostring(val)
    if text == "-1" then return "-1" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        local low = l % 0x100000000
        if low == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, low)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return text
end

print(string.format("PID: %d", to_num(make_syscall(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local sc662 = make_syscall(662)
local sc664 = make_syscall(664)
local sc660 = make_syscall(660)

local ids = memory.alloc(0x10)
local states = memory.alloc(0x10)

local function one_664(id)
    safe_wd(ids, id)
    safe_wd(states, 0x7A7A7A7A)
    local ok, ret = pcall(function() return sc664(uint64(ids), uint64(1), uint64(states)) end)
    if not ok then return "PCALL-FAIL", "PCALL-FAIL" end
    return sgn(ret), sgn(safe_rd(states))
end

-- ============================================================
-- [A] slot 0..255 with handle 0x13
-- ============================================================
print("")
print("[A] 664 id = (slot << 16) | 0x13, slot 0..255")

local seen = {}
local distinct = 0
for slot = 0, 255 do
    local ret, state = one_664(slot * 0x10000 + 0x13)
    local key = ret .. "/" .. state
    if not seen[key] then
        seen[key] = 1
        distinct = distinct + 1
        print(string.format("  slot=%-3d ret=%-24s state=%s", slot, ret, state))
    end
end
print(string.format("  distinct outcomes: %d", distinct))

-- ============================================================
-- [B] handle 0..255 with slot 0
-- ============================================================
print("")
print("[B] 664 id = handle, handle 0..255")

seen = {}
distinct = 0
for handle = 0, 255 do
    local ret, state = one_664(handle)
    local key = ret .. "/" .. state
    if not seen[key] then
        seen[key] = 1
        distinct = distinct + 1
        print(string.format("  handle=%-3d ret=%-24s state=%s", handle, ret, state))
    end
end
print(string.format("  distinct outcomes: %d", distinct))

-- ============================================================
-- [C] 660 with pointer-shaped handles and both gate offsets
-- ============================================================
print("")
print("[C] 660 handle shapes and gate offsets")

local sc477 = make_syscall(477)
local page = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local ph, pl = get_hi_lo(page)
local page_valid = not (ph == 0xFFFFFFFF and pl == 0xFFFFFFFF) and pl ~= 0
print(string.format("  page = %s valid=%s", sgn(page), tostring(page_valid)))

local info = memory.alloc(0x200)
local function try660(label, handle, gate_offset)
    for i = 0, 0x3F do safe_wq(info + i * 8, uint64(0)) end
    safe_wq(info + gate_offset, uint64(0x160))
    local ok, ret = pcall(function() return sc660(handle, uint64(0), uint64(info)) end)
    local size00 = safe_wq and safe_rd(info) or 0
    local size10 = safe_rd(info + 0x10)
    local segcount = safe_rd(info + 0x120)
    print(string.format("  %-14s handle=%-24s gate@%s ret=%-24s d00=%s d10=%s seg=%s",
        label, sgn(handle), (gate_offset == 0) and "0x00" or "0x10",
        ok and sgn(ret) or "PCALL-FAIL", sgn(size00), sgn(size10), sgn(segcount)))
end

try660("index", uint64(0x13), 0)
try660("index-g10", uint64(0x13), 0x10)
try660("pointer", page, 0)
try660("null", uint64(0), 0)
if page_valid then
    try660("pointer+0x28", uint64(pl + 0x28), 0)
end

print("")
print("=== PROBE 239a COMPLETE ===")
