-- CRASH_CLASS: MODERATE
-- PROBE 562c: Isolate source of "77" binary debug output
--
-- 561b (MapDM only, no threads): clean text output
-- 561e/562a (MapDM + thr_new child): binary output kills stdout
-- This probe: 3 isolated tests to find the source.
-- A) native.fcall_with_rax(MapDM) only
-- B) thr_new only (no MapDM)
-- C) child with thr_exit via stub (clean exit)

print("=== PROBE 562c: ISOLATE BINARY SOURCE ===")
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
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(buf, n)
    for off = 0, n-4, 4 do wd(buf + off, 0) end
end

local Z = uint64(0)
local sc20  = mk(20)
local sc73  = mk(73)
local sc477 = mk(477)
local sc455 = mk(455)
local sc593 = mk(593)

local pid = N(sc20())
print("pid=" .. pid)

-- Eboot
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc593(Z, info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Libkernel
zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc593(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local mapdm_fn = lk + uint64(0x15020)

-- Extract stub from ropchain
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local stub = nil
if rop_str then
    local rop = uint64(rop_str)
    -- Entry [3] is the stub (confirmed in 561d: eboot+0x1AEBB, appears 6 times)
    local s_lo = rb(rop + 3 * 8) or 0
    local s_hi = rb(rop + 3 * 8 + 4) or 0
    stub = uint64(string.format("0x%X%08X", s_hi, s_lo))
    print(string.format("stub=0x%X%08X (chain[3])", s_hi, s_lo))
end

local bare_ret    = eboot + uint64(0x42)
local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)
local mov_mem_rdi_rax = eboot + uint64(0x92C67)

io.flush()

-- ============================================================
-- TEST A: MapDM only (no threads)
-- ============================================================
print("")
print("--- TEST A: MapDM only ---")
io.flush()

local va_a = uint64("0x880000000")
pcall(function()
    sc477(va_a, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)

local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        va_a, uint64(0x4000), uint64(3), Z, uint64("0x100000000"), uint64(0x4000))
end)
local a_rv = ok_a and N(rv_a) or -999

print(string.format("MapDM rv=%d", a_rv))
pcall(function() sc73(va_a, uint64(0x4000)) end)
print("TEST A done")
io.flush()

-- ============================================================
-- TEST B: thr_new only (no MapDM, child writes sentinel then crashes)
-- ============================================================
print("")
print("--- TEST B: thr_new only (crash exit) ---")
io.flush()

local shared_b = memory.alloc(0x40)
zero(shared_b, 0x40)

local ss_b = 0x4000
local ok_sb, sb_b = pcall(function()
    return sc477(Z, uint64(ss_b), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local sb_bn = N(sb_b)
local rsp_bn = (sb_bn + ss_b) - ((sb_bn + ss_b) % 16) - 8
local rsp_b = sb_b + uint64(rsp_bn - sb_bn)

local ci = 0
local function wcb(val) wq(rsp_b + uint64(ci * 8), val); ci = ci + 1 end

wcb(pop_rax_ret)
wcb(uint64("0xBEEF0001"))
wcb(pop_rdi_ret)
wcb(shared_b)
wcb(mov_mem_rdi_rax)
for i = 1, 16 do wcb(bare_ret) end

local pa_b = memory.alloc(0x40)
zero(pa_b, 0x40)
wq(pa_b + 0x00, bare_ret)
wq(pa_b + 0x10, uint64(sb_b))
wq(pa_b + 0x18, uint64(ss_b))
local tid_b = memory.alloc(8)
wq(pa_b + 0x30, uint64(tid_b))

pcall(function() sc455(uint64(pa_b), uint64(0x38)) end)

for wait = 1, 1000 do
    for j = 1, 200 do local x = j * j end
    local s = rb(shared_b) or 0
    if s == 0xBEEF0001 then break end
end

local val_b = rb(shared_b) or 0
print(string.format("thr_new result: sentinel=0x%X", val_b))
pcall(function() sc73(sb_b, uint64(ss_b)) end)
print("TEST B done")
io.flush()

-- ============================================================
-- TEST C: thr_new with thr_exit via stub (clean exit)
-- ============================================================
print("")
print("--- TEST C: thr_new with thr_exit (stub) ---")
io.flush()

if stub then
    local shared_c = memory.alloc(0x40)
    zero(shared_c, 0x40)

    local ss_c = 0x4000
    local ok_sc, sb_c = pcall(function()
        return sc477(Z, uint64(ss_c), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), Z)
    end)
    local sb_cn = N(sb_c)
    local rsp_cn = (sb_cn + ss_c) - ((sb_cn + ss_c) % 16) - 8
    local rsp_c = sb_c + uint64(rsp_cn - sb_cn)

    ci = 0
    local function wcc(val) wq(rsp_c + uint64(ci * 8), val); ci = ci + 1 end

    -- Write sentinel
    wcc(pop_rax_ret)
    wcc(uint64("0xBEEF0002"))
    wcc(pop_rdi_ret)
    wcc(shared_c)
    wcc(mov_mem_rdi_rax)

    -- thr_exit(431) via stub: pop_rax_ret → 431 → stub
    wcc(pop_rax_ret)
    wcc(uint64(431))
    wcc(stub)

    -- Padding (shouldn't reach)
    for i = 1, 8 do wcc(bare_ret) end

    local pa_c = memory.alloc(0x40)
    zero(pa_c, 0x40)
    wq(pa_c + 0x00, bare_ret)
    wq(pa_c + 0x10, uint64(sb_c))
    wq(pa_c + 0x18, uint64(ss_c))
    local tid_c = memory.alloc(8)
    wq(pa_c + 0x30, uint64(tid_c))

    pcall(function() sc455(uint64(pa_c), uint64(0x38)) end)

    for wait = 1, 1000 do
        for j = 1, 200 do local x = j * j end
        local s = rb(shared_c) or 0
        if s == 0xBEEF0002 then break end
    end

    local val_c = rb(shared_c) or 0
    print(string.format("thr_exit result: sentinel=0x%X", val_c))
    pcall(function() sc73(sb_c, uint64(ss_c)) end)
    print("TEST C done")
else
    print("stub not found, skipping")
end

io.flush()
print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 562c DONE ===")
