-- CRASH_CLASS: MODERATE
-- PROBE 301a: 662/663/664 with the argument shape their contract names
--
-- The 13.60 contracts give these three handlers real arguments:
--
--   662  ids, count, results
--   663  ids, count, states, wait_mode, timeout_inout
--   664  ids, count, states
--
-- Every earlier measurement passed six zeroes, which reaches none of those
-- fields, and all three answered -1. This probe passes an ids array holding
-- our own tid, count = 1, and a mapped output buffer, then dumps whatever the
-- call writes back.
--
-- A kill takes the loader with it, so each call prints a BEFORE line and the
-- next section starts only if the previous one returned.

print("=== PROBE 301a: THREAD STATE CALLS ===")

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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, to_num(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return to_num(val) end
    return -1
end

local sc_self = make_syscall(432)
local ok, tid = pcall(function() return sc_self(uint64(0)) end)
tid = ok and tid or 0
print(string.format("[tid] thr_self -> 0x%X", to_num(tid)))

local ids   = memory.alloc(0x40)
local out   = memory.alloc(0x400)
local tout  = memory.alloc(0x40)
for i = 0, 7 do memory.write_qword(ids + i * 8, tid) end
for i = 0, 0x3FF, 8 do memory.write_qword(out + i, 0x4141414141414141) end
memory.write_qword(tout, 0)
memory.write_qword(tout + 8, 0)

local function dump(tag, base, n)
    local parts = {}
    for i = 0, n - 1 do
        parts[#parts + 1] = string.format("%X", rq(base + i * 8))
    end
    print(string.format("[%s] %s", tag, table.concat(parts, " ")))
end

local function call(tag, no, a0, a1, a2, a3, a4, a5)
    print(string.format("[BEFORE] %s sys %d", tag, no))
    local sc = make_syscall(no)
    local okc, r = pcall(function() return sc(a0, a1, a2, a3, a4, a5) end)
    if not okc then
        print(string.format("[%s] PCALL-FAIL %s", tag, tostring(r)))
        return nil
    end
    local ret = sgn(r)
    print(string.format("[%s] ret=%d", tag, ret))
    return ret
end

local Z = uint64(0)

-- 662: ids, count, results
for i = 0, 0x3FF, 8 do memory.write_qword(out + i, 0x4141414141414141) end
call("662", 662, uint64(ids), uint64(1), uint64(out), Z, Z, Z)
dump("662-out", out, 8)

-- 664: ids, count, states
for i = 0, 0x3FF, 8 do memory.write_qword(out + i, 0x4141414141414141) end
call("664", 664, uint64(ids), uint64(1), uint64(out), Z, Z, Z)
dump("664-out", out, 8)

-- 663: ids, count, states, wait_mode, timeout_inout (mode 0, zero timeout)
for i = 0, 0x3FF, 8 do memory.write_qword(out + i, 0x4141414141414141) end
call("663", 663, uint64(ids), uint64(1), uint64(out), uint64(0), uint64(tout), Z)
dump("663-out", out, 8)

-- 662 with count 0 and valid pointers
for i = 0, 0x3FF, 8 do memory.write_qword(out + i, 0x4141414141414141) end
call("662-c0", 662, uint64(ids), uint64(0), uint64(out), Z, Z, Z)
dump("662-c0-out", out, 4)

-- 662 with a kernel-shaped ids pointer
call("662-kptr", 662, uint64(string.format("0x%X%08X", 0xFFFF9000, 0)), uint64(1), uint64(out), Z, Z, Z)

print("=== DONE ===")
