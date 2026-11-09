-- CRASH_CLASS: MODERATE
-- PROBE 530g: Safely call GnmDriver functions one at a time
--
-- 530f: NID table parsed (54 functions), but calling text+0x14A crashed.
-- Most functions between text+0xA78 and text+0xF38 are small (20 bytes each).
-- The big function at text+0x14A (2.3 KB) is likely init/submit.
-- Small functions are likely simple getters/queries.
--
-- Strategy: call only the small functions (>= text+0xA78) first.
-- They're likely getters that return driver state (GPU frequency, etc.)

print("=== PROBE 530g: GNM SAFE CALL ===")
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

-- Get GnmDriver text base
local gnm_ib = memory.alloc(0x200)
wd(N(gnm_ib), 0x160)
pcall(function() mk(593)(uint64(56), gnm_ib) end)
local gnm_text_lo = rd(N(gnm_ib) + 0x108) or 0
local gnm_text_hi = rd(N(gnm_ib) + 0x10C) or 0
if gnm_text_lo < 0 then gnm_text_lo = gnm_text_lo + 0x100000000 end
if gnm_text_hi < 0 then gnm_text_hi = gnm_text_hi + 0x100000000 end
local gnm_text = uint64(string.format("0x%X%08X", gnm_text_hi, gnm_text_lo))
print("gnm_text=" .. fmt(gnm_text))

-- The small functions (text+0xA78 through text+0xF38)
-- Each is ~20 bytes, likely getters/queries
local small_funcs = {
    {0xA78, 0x40E0}, {0xA8C, 0x40F0}, {0xAA0, 0x4100}, {0xAB4, 0x4110},
    {0xAC8, 0x4120}, {0xADC, 0x4130}, {0xAF0, 0x41C0}, {0xB10, 0x41E0},
    {0xB24, 0x4200}, {0xB38, 0x4210}, {0xB4C, 0x4230}, {0xB60, 0x4250},
    {0xB74, 0x4260}, {0xB88, 0x42D0}, {0xB9C, 0x42E0}, {0xBB0, 0x4370},
    {0xBD0, 0x43E0}, {0xBF0, 0x4410}, {0xC10, 0x4420}, {0xC24, 0x4430},
    {0xC38, 0x4450}, {0xC4C, 0x4460}, {0xC60, 0x4470}, {0xC74, 0x4480},
    {0xC88, 0x4490}, {0xC9C, 0x44A0}, {0xCB0, 0x44B0}, {0xCC4, 0x44C0},
    {0xCD8, 0x44D0}, {0xCEC, 0x44E0}, {0xD00, 0x44F0}, {0xD14, 0x4500},
    {0xD28, 0x4520}, {0xD48, 0x4530}, {0xD5C, 0x4540}, {0xD70, 0x4560},
    {0xD84, 0x4570}, {0xD98, 0x4580}, {0xDAC, 0x4590}, {0xDC0, 0x45A0},
    {0xDD4, 0x45B0}, {0xDE8, 0x45C0}, {0xDFC, 0x45D0}, {0xE10, 0x45F0},
    {0xE24, 0x4600}, {0xE38, 0x4620}, {0xE4C, 0x4640}, {0xE60, 0x4650},
    {0xE78, 0x4890}, {0xEA8, 0x4A30}, {0xED8, 0x4CD0}, {0xF08, 0x4F10},
    {0xF38, 0x4F30},
}

-- ============================================================
-- [A] Call all small functions with 0 args
-- ============================================================
print("[A] Small functions (0 args)")
local results = {}

for _, f in ipairs(small_funcs) do
    local addr = gnm_text + uint64(f[1])
    local ok_c, rv_c = pcall(function()
        return native.fcall_with_rax(addr, 0)
    end)
    local ret = -999
    local ret_hi = 0
    if ok_c and rv_c then
        ret = N(rv_c)
        local rh, rl = get_hi_lo(rv_c)
        if rh < 0 then rh = rh + 0x100000000 end
        ret_hi = rh
    end

    table.insert(results, {off = f[1], nid = f[2], ok = ok_c, ret = ret, ret_hi = ret_hi})

    local tag = ""
    if not ok_c then tag = "CRASH"
    elseif ret == 0 then tag = "zero"
    elseif ret > 0 and ret < 100 then tag = "small_int"
    elseif ret > 100000 and ret < 1000000000 then tag = "large_int"
    elseif ret_hi > 0 then tag = "ptr?"
    else tag = string.format("0x%X", ret >= 0 and ret or 0)
    end

    print(string.format("  +0x%04X NID 0x%04X: %s rv=%d (%s)",
        f[1], f[2], ok_c and "OK" or "XX", ret, tag))
end

-- ============================================================
-- [B] Summary
-- ============================================================
print("")
print("[B] Summary")
local safe = 0
local crashed = 0
local zero_ret = 0
for _, r in ipairs(results) do
    if r.ok then safe = safe + 1
        if r.ret == 0 then zero_ret = zero_ret + 1 end
    else crashed = crashed + 1 end
end
print(string.format("  safe=%d crashed=%d returned_0=%d", safe, crashed, zero_ret))

-- ============================================================
-- [C] For functions that returned large values, interpret them
-- ============================================================
print("")
print("[C] Interesting returns")
for _, r in ipairs(results) do
    if r.ok and r.ret ~= 0 and r.ret ~= -999 then
        local val = r.ret
        if val < 0 then val = val + 0x100000000 end
        local mhz = math.floor(val / 1000000)
        local khz = math.floor(val / 1000)
        print(string.format("  +0x%04X NID 0x%04X: %d (%d MHz / %d KHz / 0x%X)",
            r.off, r.nid, r.ret, mhz, khz, val))
    end
end

print("")
print("=== 530g DONE ===")
