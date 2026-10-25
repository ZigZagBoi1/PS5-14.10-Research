-- CRASH_CLASS: LOW
-- PROBE 530e: Find GPU ring buffer and doorbell in process VM map
--
-- The game process has the GPU initialized. The GNM driver maps:
-- 1. A doorbell page (for submitting commands to GPU)
-- 2. The GPU ring buffer (where PM4 packets go)
-- 3. GPU MMIO registers (for control)
--
-- sys 674 gives the full VM map. We need to find non-heap, non-stack
-- regions that look like GPU mappings.
--
-- Also: read GnmDriver .data (type=3) for internal state including
-- ring buffer addresses and doorbell pointers.
--
-- Strategy:
-- 1. Get full VM map from sys 674 and identify GPU-related regions
-- 2. Read GnmDriver .data section (readable) for ring/doorbell ptrs
-- 3. Find the write pointer/doorbell and inject our own command

print("=== PROBE 530e: GPU RING + DOORBELL ===")
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
-- [A] GnmDriver .data section internal state
-- ============================================================
print("[A] GnmDriver .data internal state")

local sc_649 = mk(649)
local gnm_ib = memory.alloc(0x200)
wd(N(gnm_ib), 0x160)
pcall(function() mk(593)(uint64(56), gnm_ib) end)
local gnm_text_lo = rd(N(gnm_ib) + 0x108) or 0
local gnm_text_hi = rd(N(gnm_ib) + 0x10C) or 0
if gnm_text_lo < 0 then gnm_text_lo = gnm_text_lo + 0x100000000 end
if gnm_text_hi < 0 then gnm_text_hi = gnm_text_hi + 0x100000000 end
print(string.format("  gnm text=0x%X%08X", gnm_text_hi, gnm_text_lo))

-- type=3 = .data start, type=4 = .data section info
local data_tb = memory.alloc(8)
pcall(function() sc_649(uint64(56), uint64(3), uint64(data_tb)) end)
local gnm_data = rq(N(data_tb))
print("  gnm .data=" .. fmt(gnm_data))

local gnm_data_n = N(gnm_data)

-- Read first 512 bytes of GnmDriver .data — this should have internal structs
print("  First 128 bytes of GnmDriver .data:")
local interesting_ptrs = {}
for off = 0, 0x200 - 8, 8 do
    local v = rq(gnm_data_n + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end

        local tag = ""
        -- Categorize
        if vh == 0 and vl == 0 then
            -- skip zeros
        else
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                tag = " <KPTR!>"
            elseif vh == gnm_text_hi and vl >= gnm_text_lo and vl < gnm_text_lo + 0xC000 then
                tag = string.format(" <gnm_text+0x%X>", vl - gnm_text_lo)
            elseif vh >= 1 and vh <= 0x10 then
                tag = " <UPTR>"
            elseif vl ~= 0 or vh ~= 0 then
                tag = ""
            end

            table.insert(interesting_ptrs, {off, vh, vl, tag})
            if #interesting_ptrs <= 40 then
                print(string.format("  [+0x%03X] 0x%08X%08X%s", off, vh, vl, tag))
            end
        end
    end
end
if #interesting_ptrs > 40 then
    print(string.format("  ... %d total non-zero entries", #interesting_ptrs))
end

-- ============================================================
-- [B] Deeper .data scan — look for addresses that might be
-- GPU ring buffers (typically 256 KB to 4 MB aligned)
-- ============================================================
print("")
print("[B] GnmDriver .data deeper scan (2 KB)")

local ring_candidates = {}
for off = 0, 0x800 - 8, 8 do
    local v = rq(gnm_data_n + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end

        -- Ring buffers are typically page-aligned pointers in user space
        if vh >= 1 and vh <= 0x10 and vl % 0x4000 == 0 and vl ~= 0 then
            table.insert(ring_candidates, {off, vh, vl})
            -- Try reading that address
            local rd_val = rd(vh * 0x100000000 + vl)
            local rd_str = "FAULT"
            if rd_val then
                if rd_val < 0 then rd_val = rd_val + 0x100000000 end
                rd_str = string.format("0x%08X", rd_val)
                -- Check if it looks like PM4
                if math.floor(rd_val / 0x40000000) % 4 == 3 then
                    rd_str = rd_str .. " <PM4!>"
                end
            end
            print(string.format("  [+0x%03X] ptr=0x%X%08X -> %s", off, vh, vl, rd_str))
        end
    end
end
print(string.format("  aligned pointer candidates: %d", #ring_candidates))

-- ============================================================
-- [C] Try reading the GnmDriver .data as a whole struct
-- PS5 GNM context typically stores: pipe_id, queue_base, queue_size,
-- write_ptr, read_ptr, doorbell_offset
-- ============================================================
print("")
print("[C] GnmDriver struct interpretation")

-- type=8 from 649 — on PS5 this often points to the end of the module or proc_param
local type8_buf = memory.alloc(8)
pcall(function() sc_649(uint64(56), uint64(8), uint64(type8_buf)) end)
local gnm_type8 = rq(N(type8_buf))
print("  gnm type=8: " .. fmt(gnm_type8))

-- The init function (type=1) is at text+0x10
-- Let's try reading type=7 (module base)
local type7_buf = memory.alloc(8)
pcall(function() sc_649(uint64(56), uint64(7), uint64(type7_buf)) end)
local gnm_type7 = rq(N(type7_buf))
print("  gnm type=7 (module base): " .. fmt(gnm_type7))

-- Read around module base for ELF/PRX headers (if readable)
local base_n = N(gnm_type7)
local hdr_val = rd(base_n)
if hdr_val then
    if hdr_val < 0 then hdr_val = hdr_val + 0x100000000 end
    print(string.format("  module[0]=0x%08X (%s)", hdr_val,
        hdr_val == 0x464C457F and "ELF!" or "not ELF"))
else
    print("  module[0]=FAULT (XO)")
end

-- ============================================================
-- [D] Look for the SubmitCommandBuffers by calling GnmDriver
-- functions found in its .data section
-- ============================================================
print("")
print("[D] GnmDriver .data function pointers — try calling")

local gnm_funcs = {}
for off = 0, 0x800 - 8, 8 do
    local v = rq(gnm_data_n + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        if vh == gnm_text_hi and vl >= gnm_text_lo and vl < gnm_text_lo + 0xC000 then
            table.insert(gnm_funcs, {off, vl - gnm_text_lo, vh, vl})
        end
    end
end

print(string.format("  gnm text pointers in .data: %d", #gnm_funcs))

-- Call each with 0 args — look for ones that return small ints
-- (query functions, counters) vs ones that crash (need args)
for i, f in ipairs(gnm_funcs) do
    if i > 15 then break end
    local func_addr = uint64(string.format("0x%X%08X", f[3], f[4]))
    local ok_c, rv_c = pcall(function()
        return native.fcall_with_rax(func_addr, 0)
    end)
    local ret = -999
    if ok_c and rv_c then ret = N(rv_c) end
    print(string.format("  .data+0x%03X -> text+0x%04X: %s rv=%d",
        f[1], f[2], ok_c and "ok" or "CRASH", ret))
end

print("")
print("=== 530e DONE ===")
