-- CRASH_CLASS: MODERATE
-- PROBE 530c: Call GnmDriver submit functions directly
--
-- 530a/530b: ioctl 0xC0108102 accepts but GPU doesn't execute.
-- The ioctl probably just enqueues — the real submit goes through
-- sceGnmSubmitCommandBuffers which handles the full setup + doorbell.
--
-- GnmDriver exports (sys 649):
--   type=1 (init): 0x82B660010
--   type=2 (func table): 0x82B668820
--   type=3 (.data start): 0x82B66C000
--   type=4 (.data end?): 0x82B66CA60
--
-- type=2 is a table of function pointers (NID hash → address).
-- We'll read the table to find callable functions.
-- Also: try calling GnmDriver's init function first.

print("=== PROBE 530c: GNM SUBMIT DIRECT ===")
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
-- [A] Read GnmDriver function table
-- ============================================================
print("[A] GnmDriver function table")

-- First, get GnmDriver module info
local gnm_ib = memory.alloc(0x200)
wd(N(gnm_ib), 0x160)
pcall(function() mk(593)(uint64(56), gnm_ib) end)
local gnm_text_lo = rd(N(gnm_ib) + 0x108) or 0
local gnm_text_hi = rd(N(gnm_ib) + 0x10C) or 0
if gnm_text_lo < 0 then gnm_text_lo = gnm_text_lo + 0x100000000 end
if gnm_text_hi < 0 then gnm_text_hi = gnm_text_hi + 0x100000000 end
local gnm_text = uint64(string.format("0x%X%08X", gnm_text_hi, gnm_text_lo))
print("  gnm text=" .. fmt(gnm_text))

-- type=2 gives the export/function table
local sc_649 = mk(649)
local type2_buf = memory.alloc(0x10)
wq(N(type2_buf), uint64(0))
pcall(function() sc_649(uint64(56), uint64(2), uint64(type2_buf)) end)
local func_table = rq(N(type2_buf))
print("  func_table=" .. fmt(func_table))

-- The table format for PS5 modules (PRX/SPRX) is typically:
-- Array of { uint64 nid_hash, uint64 func_addr } entries
-- OR it could be a flat array of function pointers

-- Read first 128 entries (16 bytes each = 2 KB)
local ft_base = N(func_table)
local funcs = {}
local text_base_n = gnm_text_hi * 0x100000000 + gnm_text_lo

print("  First 32 qwords from func_table:")
for i = 0, 31 do
    local v = rq(ft_base + i * 8)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        local combined = vh * 0x100000000 + vl

        -- Check if it's a pointer into GnmDriver text
        local is_text = (vh == gnm_text_hi and vl >= gnm_text_lo and vl < gnm_text_lo + 0xC000)
        local tag = ""
        if is_text then
            local off = vl - gnm_text_lo
            tag = string.format(" -> text+0x%X", off)
            table.insert(funcs, {i, off, vh, vl})
        end

        print(string.format("  [%d] 0x%08X%08X%s", i, vh, vl, tag))
    end
end

-- ============================================================
-- [B] Also read type=1 and type=4 tables
-- ============================================================
print("")
print("[B] Other module table addresses")

for _, mtype in ipairs({1, 3, 4, 7, 8}) do
    local tb = memory.alloc(0x10)
    wq(N(tb), uint64(0))
    pcall(function() sc_649(uint64(56), uint64(mtype), uint64(tb)) end)
    local v = rq(N(tb))
    if v then
        print(string.format("  type=%d: %s", mtype, fmt(v)))
        -- Read first few values
        local base = N(v)
        for j = 0, 3 do
            local q = rq(base + j * 8)
            if q then
                local qh, ql = get_hi_lo(q)
                if qh < 0 then qh = qh + 0x100000000 end
                if ql < 0 then ql = ql + 0x100000000 end
                local is_text = (qh == gnm_text_hi and ql >= gnm_text_lo and ql < gnm_text_lo + 0xC000)
                if is_text then
                    print(string.format("    [%d] 0x%08X%08X -> text+0x%X", j, qh, ql, ql - gnm_text_lo))
                else
                    print(string.format("    [%d] 0x%08X%08X", j, qh, ql))
                end
            end
        end
    end
end

-- ============================================================
-- [C] Read GnmDriver .data section for function pointers (GOT)
-- ============================================================
print("")
print("[C] GnmDriver .data GOT entries")

-- type=3 is .data start
local data_buf = memory.alloc(0x10)
wq(N(data_buf), uint64(0))
pcall(function() sc_649(uint64(56), uint64(3), uint64(data_buf)) end)
local data_base = rq(N(data_buf))
print("  .data base=" .. fmt(data_base))

local data_n = N(data_base)
local got_entries = {}

-- Scan first 2 KB of .data for function pointers
for off = 0, 0x800 - 8, 8 do
    local v = rq(data_n + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end

        -- Pointer into GnmDriver text?
        local is_gnm = (vh == gnm_text_hi and vl >= gnm_text_lo and vl < gnm_text_lo + 0xC000)
        if is_gnm then
            local text_off = vl - gnm_text_lo
            table.insert(got_entries, {off, text_off})
            print(string.format("    .data+0x%03X -> gnm_text+0x%X", off, text_off))
        end

        -- Pointer into libkernel?
        if vh >= 8 and vh <= 9 then
            -- Could be a lib pointer
            if (vl ~= 0 or vh ~= 0) and vl % 0x10 == 0 then
                -- Potentially interesting
            end
        end
    end
end

print(string.format("  GnmDriver GOT: %d text pointers", #got_entries))

-- ============================================================
-- [D] Try calling the first few GnmDriver functions
-- Use fcall_with_rax to call them safely with 0 args
-- ============================================================
print("")
print("[D] Call GnmDriver functions (cautious)")

-- Only call functions that look like query/info (not submit/init)
-- Start with smaller text offsets (simpler functions)
if #funcs > 0 then
    -- Sort by text offset
    table.sort(funcs, function(a, b) return a[2] < b[2] end)

    for i, f in ipairs(funcs) do
        if i > 10 then break end
        local func_addr = uint64(string.format("0x%X%08X", f[3], f[4]))
        local ok_c, rv_c = pcall(function()
            return native.fcall_with_rax(func_addr, 0)
        end)
        local ret = rv_c and N(rv_c) or -999
        print(string.format("  text+0x%04X: ok=%s rv=%d (0x%X)",
            f[2], tostring(ok_c), ret, ret >= 0 and ret or 0))
    end
end

-- ============================================================
-- [E] Check if GnmDriver text is RX or XO
-- ============================================================
print("")
print("[E] GnmDriver text readability")
local test_d = rd(N(gnm_text))
if test_d then
    if test_d < 0 then test_d = test_d + 0x100000000 end
    print(string.format("  gnm_text[0]=0x%08X — RX (readable)", test_d))
else
    print("  gnm_text[0]=FAULT — XO (not readable)")
end

print("")
print("=== 530c DONE ===")
