-- CRASH_CLASS: LOW
-- PROBE 706a: does 14.10 implement 619 test_debug_rwmem / 652, and does the
-- SIGSYS shield turn the absent slots into plain -1?
--
-- Context: in the 13.60 capture 619 is the ENOSYS stub (mov eax,0x4e; ret) with
-- narg 5. If Sony implemented it on 14.10 it would be literal kernel R/W, so the
-- cheap question is whether the slot now does anything. sigaction(12, SIG_IGN)
-- makes an absent slot return -1 instead of killing the process (353a), which
-- lets one connection test several shapes safely.
--
-- Every call is preceded by a marker line so the last line on disk names the
-- call that killed the process.

print("=== PROBE 706a: 619 / 652 slot survey under SIGSYS shield ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function u64(addr)
    local h, l = get_hi_lo(addr)
    return uint64(string.format("0x%X%08X", h, l))
end

-- shield: ignore SIGSYS so an absent slot returns ENOSYS instead of dying
local sc_sig = make_syscall(416)
local ok_shield = pcall(function() sc_sig(uint64(12), uint64(1), uint64(0), uint64(0)) end)
print("[S] sigaction(12, SIG_IGN) ok=" .. tostring(ok_shield))

local buf = memory.alloc(0x1000)
for i = 0, 0x3FF do
    memory.write_dword(buf + i * 4, 0xDEADBEEF)
end
local addr = uint64(string.format("0x%X", to_num(buf)))

local function probe(num, args_desc, ...)
    print("[*] sys " .. num .. " " .. args_desc)
    local a = {...}
    local sc = make_syscall(num)
    local ok, ret = pcall(function() return sc(unpack(a)) end)
    if not ok then
        print("    PCALL-FAIL")
        return false
    end
    print("    ret=" .. tostring(ret) ..
          string.format("  buf[0]=%08X buf[4]=%08X", safe_rd(buf) or 0, safe_rd(buf + 4) or 0))
    return true
end

local z = uint64(0)
local n = uint64(0x100)

-- 619: try the obvious (addr, buf, len) and its permutations
probe(619, "(buf, 0x100, 0, 0, 0)", addr, n, z, z, z)
probe(619, "(0, buf, 0x100, 0, 0)", z, addr, n, z, z)
probe(619, "(buf, 0x100, 0, 0, 1)", addr, n, z, z, uint64(1))
probe(619, "(0, 0, buf, 0x100, 0)", z, z, addr, n, z)

-- 652: unknown "debug" slot, same permutations
probe(652, "(buf, 0x100, 0, 0, 0)", addr, n, z, z, z)
probe(652, "(0, buf, 0x100, 0, 0)", z, addr, n, z, z)

-- control: a definitely-absent slot must answer -1 under the shield
probe(4095, "(0,0,0,0,0)", z, z, z, z, z)

print("[done] alive")
