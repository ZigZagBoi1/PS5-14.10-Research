-- CRASH_CLASS: MODERATE
-- PROBE 302a: 662/663/664 with a real thread id
--
-- 301a gave these three handlers the shape their contract names and got
-- ret=0 with the dword 0x80020000 written into the results buffer - a Sony
-- error, because the ids it passed were 0xFFFFFFFFFFFFFFFF: thr_self was
-- called with a null out-pointer and failed.
--
-- This probe takes the tid properly (432 writes it to a buffer), then asks
-- each handler about it. The last section passes count = 0x400 against a
-- one-page ids array to see whether the handler bounds the count it is given.

print("=== PROBE 302a: THREAD STATE IDS ===")

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
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end

local tidbuf = memory.alloc(0x40)
for i = 0, 0x3F, 8 do memory.write_qword(tidbuf + i, 0x4242424242424242) end
local sc_self = make_syscall(432)
local okr, rv = pcall(function() return sc_self(uint64(tidbuf)) end)
local tid = rq(tidbuf)
print(string.format("[tid] 432(buf) ret=%s buf[0]=0x%X buf[8]=0x%X",
    tostring(okr and sgn(rv) or "fail"), tid, rq(tidbuf + 8)))

local ids  = memory.alloc(0x1000)
local out  = memory.alloc(0x400)
local tout = memory.alloc(0x40)
for i = 0, 0xFFF, 8 do memory.write_qword(ids + i, tid) end
for i = 0, 0x3FF, 8 do memory.write_qword(out + i, 0x4141414141414141) end
memory.write_qword(tout, 0)
memory.write_qword(tout + 8, 0)

local function dump(tag, base, n)
    local parts = {}
    for i = 0, n - 1 do parts[#parts + 1] = string.format("%X", rd(base + i * 4)) end
    print(string.format("[%s] %s", tag, table.concat(parts, " ")))
end

local function call(tag, no, a0, a1, a2, a3, a4)
    print(string.format("[BEFORE] %s sys %d", tag, no))
    local sc = make_syscall(no)
    local okc, r = pcall(function() return sc(a0, a1, a2, a3, a4, uint64(0)) end)
    if not okc then
        print(string.format("[%s] PCALL-FAIL %s", tag, tostring(r)))
        return nil
    end
    local ret = sgn(r)
    print(string.format("[%s] ret=%d", tag, ret))
    return ret
end

-- 662: ids, count, results
for i = 0, 0x3FF, 8 do memory.write_qword(out + i, 0x4141414141414141) end
call("662-1", 662, uint64(ids), uint64(1), uint64(out), uint64(0), uint64(0))
dump("662-1-out", out, 8)

-- 664: ids, count, states
for i = 0, 0x3FF, 8 do memory.write_qword(out + i, 0x4141414141414141) end
call("664-1", 664, uint64(ids), uint64(1), uint64(out), uint64(0), uint64(0))
dump("664-1-out", out, 8)

-- 663: ids, count, states, wait_mode 0, timeout 0
for i = 0, 0x3FF, 8 do memory.write_qword(out + i, 0x4141414141414141) end
call("663-1", 663, uint64(ids), uint64(1), uint64(out), uint64(0), uint64(tout))
dump("663-1-out", out, 8)

-- 662 with four copies of the tid
for i = 0, 0x3FF, 8 do memory.write_qword(out + i, 0x4141414141414141) end
call("662-4", 662, uint64(ids), uint64(4), uint64(out), uint64(0), uint64(0))
dump("662-4-out", out, 8)

-- count larger than the ids page: does the handler bound it?
call("662-big", 662, uint64(ids), uint64(0x400), uint64(out), uint64(0), uint64(0))

print("=== DONE ===")
