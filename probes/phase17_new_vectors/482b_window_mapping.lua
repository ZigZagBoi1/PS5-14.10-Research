-- CRASH_CLASS: LOW
-- PROBE 482b: can a game obtain an address in 0x2500000000..0x2558000001 ?
--
-- 481a showed 0x80108002 / 0x80108015 / 0xC010801A return 0 when q0 is zero and
-- -1 when q0 is a heap page. The 13.60 body at 0x3d2213 tests
--   rcx = q0 + 0xffffffdb00000000 ; accept iff rcx < 0x58000001
-- which is q0 in [0x2500000000, 0x2558000001).
-- 482a's filter was 32-bit garbage, so this re-asks the question properly:
--   [A] walk sys 674 records, compare full 64-bit ends against the window
--   [B] try to read the window start
--   [C] try mmap with a hint inside the window and see where it lands
print("=== PROBE 482b: window mapping ===")
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
local function uint64_pair(hi, lo)
    return uint64(string.format("0x%08X%08X", hi, lo))
end
local function q(addr)
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if not ok or v == nil then return 0, 0 end
    if type(v) == "table" and v.h then
        return to_num(v.h), to_num(v.l)
    end
    local n = to_num(v)
    return math.floor(n / 4294967296), n % 4294967296
end
local function safe_rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return nil
end
local function safe_wd(addr, val)
    return pcall(function() memory.write_dword(addr, val) end)
end

local W_LO_HI, W_LO_LO = 0x25, 0x00000000      -- 0x2500000000
local W_HI_HI, W_HI_LO = 0x25, 0x58000001      -- 0x2558000001

-- [A] region walk
print("[A] sys 674 window filter")
local sc674 = make_syscall(674)
local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
local countp = memory.alloc(16)
pcall(function() memory.write_qword(countp, uint64(0)) end)
local ret = -1
pcall(function()
    ret = sc674(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
end)
local n = safe_rd(countp)
print(string.format("    ret=%s count=%s", tostring(ret), tostring(n)))
if type(n) == "number" and n > MAX then n = MAX end
local hits = 0
for i = 0, (n or 0) - 1 do
    local rec = buf + i * STRIDE
    local sh, sl = q(rec)
    local eh, el = q(rec + 8)
    local prot = safe_rd(rec + 0x18) or -1
    -- does [start,end) intersect the window?
    local end_above_lo = (eh > W_LO_HI) or (eh == W_LO_HI and el > W_LO_LO)
    local start_below_hi = (sh < W_HI_HI) or (sh == W_HI_HI and sl < W_HI_LO)
    if end_above_lo and start_below_hi then
        hits = hits + 1
        print(string.format("    HIT %d start=%08X%08X end=%08X%08X prot=%X",
            i, sh, sl, eh, el, prot))
    end
end
print(string.format("    regions intersecting window: %d", hits))

-- [B] can we read the window start?
print("")
print("[B] read window start")
local wp = uint64_pair(0x25, 0x00000000)
local v = safe_rd(wp)
print(string.format("    read_dword(0x2500000000) = %s", tostring(v)))
local okq, vq = pcall(function() return memory.read_qword(uint64_pair(0x25, 0x50000000)) end)
print(string.format("    read_qword(0x2550000000) ok=%s val=%s", tostring(okq), tostring(vq)))

-- [C] mmap hint inside the window
print("")
print("[C] mmap with a hint inside the window")
local sc_mmap = make_syscall(477)
local hints = { 0x2500000000, 0x2520000000, 0x2550000000 }
for _, hint in ipairs(hints) do
    local hi = math.floor(hint / 4294967296)
    local lo = hint % 4294967296
    local ok, r = pcall(function()
        return sc_mmap(uint64_pair(hi, lo), uint64(0x40000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local rh, rl = 0, 0
    if ok and r ~= nil then
        if type(r) == "table" and r.h then rh, rl = to_num(r.h), to_num(r.l)
        else local x = to_num(r); rh = math.floor(x / 4294967296); rl = x % 4294967296 end
    end
    print(string.format("    hint=%08X%08X ok=%s -> %08X%08X", hi, lo, tostring(ok), rh, rl))
end

print("")
print("[D] write into the first mapping that answered, if any")
print("=== PROBE 482b DONE ===")
