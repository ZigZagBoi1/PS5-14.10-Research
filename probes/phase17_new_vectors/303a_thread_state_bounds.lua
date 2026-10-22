-- CRASH_CLASS: HIGH
-- PROBE 303a: what id does 662 accept, and does it bound the write?
--
-- 302a: 662/663/664 return 0 and write one status dword per id. A valid
-- thr_self tid (0x18E65) still produced 0x80020003, and count = 0x400 against
-- a 0x1000 ids page returned -1 instead of dying, so the id read is bounded.
--
-- [A]/[B] try the process id as the id, in case these handlers key on a
-- process rather than a kernel thread.
-- [C] puts the results buffer at the end of a mapped page with count = 4: the
-- call must write 16 bytes starting 4 bytes before the end, so 12 of them land
-- one page past the buffer. A -1 means the kernel checked the range; a 0 means
-- it wrote through, and a death means it wrote into unmapped memory.

print("=== PROBE 303a: THREAD STATE BOUNDS ===")

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
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return to_num(val) end
    return -1
end

local tidbuf = memory.alloc(0x40)
local sc_self = make_syscall(432)
pcall(function() return sc_self(uint64(tidbuf)) end)
local tid = rq(tidbuf)

local sc_pid = make_syscall(20)
local okp, pv = pcall(function() return sc_pid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local pid = okp and sgn(pv) or -1
print(string.format("[ids] tid=0x%X pid=0x%X", tid, pid))

local ids = memory.alloc(0x1000)
local out = memory.alloc(0x1000)
local function fill_ids(v)
    for i = 0, 0xFFF, 8 do memory.write_qword(ids + i, v) end
end
local function clear_out()
    for i = 0, 0xFFF, 8 do memory.write_qword(out + i, 0x4141414141414141) end
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

-- [A] the process id as the id
fill_ids(uint64(pid))
clear_out()
call("A-pid", 662, uint64(ids), uint64(1), uint64(out), uint64(0), uint64(0))
print(string.format("[A-pid-out] out[0]=0x%X", rd(out)))

-- [B] thread id and process id side by side, count 2
memory.write_qword(ids, tid)
memory.write_qword(ids + 8, pid)
clear_out()
call("B-both", 662, uint64(ids), uint64(2), uint64(out), uint64(0), uint64(0))
print(string.format("[B-both-out] out[0]=0x%X out[1]=0x%X", rd(out), rd(out + 4)))

-- [C] results buffer four bytes before the end of the page, count 4
local edge = out + 0x1000 - 4
memory.write_qword(ids, tid)
for i = 1, 3 do memory.write_qword(ids + i * 8, tid) end
print("[C] edge=" .. tostring(edge) .. " (page ends 4 bytes later)")
call("C-edge", 662, uint64(ids), uint64(4), uint64(edge), uint64(0), uint64(0))
print(string.format("[C-edge-out] edge[0]=0x%X", rd(edge)))

print("=== DONE ===")
