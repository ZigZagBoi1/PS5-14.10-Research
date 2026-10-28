-- CRASH_CLASS: LOW
-- PROBE 530d: Find GnmDriver functions via eboot's GOT
--
-- 530c: GnmDriver .text is XO — can't read func_table at type=2 address.
-- But the eboot DOES import GnmDriver functions, and those are resolved
-- in the eboot's GOT (which is in .data = readable).
--
-- eboot.bin: text=0x024CE4000 (varies per session), .data follows.
-- The GOT contains resolved addresses of imported functions.
--
-- Strategy:
-- 1. Find eboot .data section
-- 2. Scan for pointers into GnmDriver's text range
-- 3. These are the resolved GOT entries for GnmDriver imports
-- 4. Try calling them (they include sceGnmSubmitCommandBuffers)
--
-- Also: try calling GnmDriver functions via dynlib_dlsym (sys 591)
-- with known NID hashes for GNM functions.

print("=== PROBE 530d: EBOOT GNM GOT ===")
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
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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

-- ============================================================
-- [A] Get module bases
-- ============================================================
print("[A] Module bases")

local sc_593 = mk(593)
local modules = {}

for _, h in ipairs({0, 56}) do  -- eboot(0), GnmDriver(56)
    local ib = memory.alloc(0x200)
    wd(N(ib), 0x160)
    pcall(function() sc_593(uint64(h), ib) end)

    local name = ""
    for i = 0, 31 do
        local b = rd(N(ib) + 8 + i)
        if b then local c = b % 256; if c == 0 then break end
            if c >= 32 and c < 127 then name = name .. string.char(c) end
        end
    end

    local text_lo = rd(N(ib) + 0x108) or 0
    local text_hi = rd(N(ib) + 0x10C) or 0
    if text_lo < 0 then text_lo = text_lo + 0x100000000 end
    if text_hi < 0 then text_hi = text_hi + 0x100000000 end
    local text_size = rd(N(ib) + 0x110) or 0
    if text_size < 0 then text_size = text_size + 0x100000000 end

    local data_lo = rd(N(ib) + 0x120) or 0
    local data_hi = rd(N(ib) + 0x124) or 0
    if data_lo < 0 then data_lo = data_lo + 0x100000000 end
    if data_hi < 0 then data_hi = data_hi + 0x100000000 end
    local data_size = rd(N(ib) + 0x128) or 0
    if data_size < 0 then data_size = data_size + 0x100000000 end

    modules[h] = {
        name = name,
        text_hi = text_hi, text_lo = text_lo, text_size = text_size,
        data_hi = data_hi, data_lo = data_lo, data_size = data_size
    }
    print(string.format("  h=%d %s text=0x%X%08X+0x%X data=0x%X%08X+0x%X",
        h, name, text_hi, text_lo, text_size, data_hi, data_lo, data_size))
end

local eboot = modules[0]
local gnm = modules[56]

if not eboot or not gnm then print("MODULE FAIL"); return end

-- ============================================================
-- [B] Scan eboot .data for GnmDriver text pointers
-- ============================================================
print("")
print("[B] Eboot .data scan for GnmDriver pointers")

local eboot_data_base = eboot.data_hi * 0x100000000 + eboot.data_lo
local gnm_text_lo = gnm.text_lo
local gnm_text_hi = gnm.text_hi
local gnm_text_end = gnm_text_lo + gnm.text_size

-- Limit scan to avoid timeout — eboot .data can be large
-- GOT is typically in the first 64 KB of .data
local scan_size = math.min(eboot.data_size, 0x10000)
print(string.format("  scanning %d bytes of eboot .data", scan_size))

local gnm_ptrs = {}
for off = 0, scan_size - 8, 8 do
    local v = rq(eboot_data_base + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        if vh == gnm_text_hi and vl >= gnm_text_lo and vl < gnm_text_end then
            local text_off = vl - gnm_text_lo
            table.insert(gnm_ptrs, {off, text_off, vh, vl})
        end
    end
end

print(string.format("  GnmDriver GOT entries: %d", #gnm_ptrs))
for i, p in ipairs(gnm_ptrs) do
    if i > 30 then break end
    print(string.format("  .data+0x%04X -> gnm_text+0x%04X (0x%X%08X)",
        p[1], p[2], p[3], p[4]))
end

-- ============================================================
-- [C] Call each GnmDriver function with 0 args to see what it returns
-- Some are queries that return info without side effects
-- ============================================================
print("")
print("[C] Call GnmDriver functions (0 args)")

for i, p in ipairs(gnm_ptrs) do
    if i > 20 then break end
    local func_addr = uint64(string.format("0x%X%08X", p[3], p[4]))
    local ok_c, rv_c = pcall(function()
        return native.fcall_with_rax(func_addr, 0)
    end)
    local ret = -999
    if ok_c and rv_c then ret = N(rv_c) end
    local ret_hex = ""
    if ret >= 0 and ret < 0x100000000 then
        ret_hex = string.format(" (0x%X)", ret)
    end
    print(string.format("  gnm+0x%04X: %s rv=%d%s",
        p[2], ok_c and "ok" or "CRASH", ret, ret_hex))
end

-- ============================================================
-- [D] Also scan for VideoOut pointers (libSceVideoOut handle=55)
-- ============================================================
print("")
print("[D] VideoOut GOT entries")

local vo_ib = memory.alloc(0x200)
wd(N(vo_ib), 0x160)
pcall(function() sc_593(uint64(55), vo_ib) end)
local vo_text_lo = rd(N(vo_ib) + 0x108) or 0
local vo_text_hi = rd(N(vo_ib) + 0x10C) or 0
if vo_text_lo < 0 then vo_text_lo = vo_text_lo + 0x100000000 end
if vo_text_hi < 0 then vo_text_hi = vo_text_hi + 0x100000000 end
local vo_text_size = rd(N(vo_ib) + 0x110) or 0
if vo_text_size < 0 then vo_text_size = vo_text_size + 0x100000000 end

local vo_ptrs = {}
for off = 0, scan_size - 8, 8 do
    local v = rq(eboot_data_base + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        if vh == vo_text_hi and vl >= vo_text_lo and vl < vo_text_lo + vo_text_size then
            table.insert(vo_ptrs, {off, vl - vo_text_lo, vh, vl})
        end
    end
end

print(string.format("  VideoOut GOT entries: %d", #vo_ptrs))
for i, p in ipairs(vo_ptrs) do
    if i > 10 then break end
    print(string.format("  .data+0x%04X -> vo_text+0x%04X", p[1], p[2]))
end

print("")
print("=== 530d DONE ===")
