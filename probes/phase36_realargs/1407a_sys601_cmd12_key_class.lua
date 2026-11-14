-- CRASH_CLASS: HIGH
-- PROBE 1407a: 601 cmd 0x12 - is the +0x08 key a pid/tid? (a process-control lookup)
--
-- prior art:
--   results/phase36_realargs/1406a_sys601_cmd12_qword8_20261109_152629.txt
--     struct+0x08 is consumed as a SCALAR: zero = EFAULT(14), every non-zero value =
--     ENOENT(2), including a mapped user page, the kernel stub, the kernel image base and
--     an unmapped kernel VA - so the value is never dereferenced, it is a key.
--   results/phase36_realargs/1404a_sys601_cmd12_index_20261109_152525.txt
--     601(0x12, 0, struct) is the only accepted index; 0x01..0xFFFFFFFF = EINVAL(22).
--   docs/MDBG_601_COMMAND_MAP_14_10.md   results/kernel_handlers/analysis/sys_601_deep.md
--
-- 601 is Sony's process-control / debugger multiplexer (13.60: 0x00 state, 0x05 0xb8-byte
-- proc info, 0x0D thread list, 0x10 alloc+copyout).  The measured 14.10 shape "refuse a
-- zero key, answer ENOENT for an unknown key" is exactly a lookup, and the first candidate
-- is a process id.  If our own pid resolves, the answer and the written bytes become a
-- process-info channel; if every pid answers ENOENT, the object being looked up is not a
-- process and the key class is something else.
--
-- Keys tried: our pid, 1, 2, small ints, our tid (thr_self), the value 0x00 writes (0x100),
-- and pid<<32 | flag combinations.  The struct's qword0 is ALSO set to a mapped page in a
-- second pass, so a successful lookup has somewhere to write.

print("=== PROBE 1407a: 601 CMD 0x12 KEY CLASS ===")

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
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function safe_wd(a, v) local ok = pcall(function() memory.write_dword(a, v) end) return ok end
local function safe_wq(a, v) local ok = pcall(function() memory.write_qword(a, v) end) return ok end
local function safe_rd(a) local ok, v = pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return -1 end
local function sgn(val)
    if val == nil then return "nil" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        local lo = l % 0x100000000
        if lo == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, lo)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return tostring(val)
end

local sc601 = make_syscall(601)
local sc477 = make_syscall(477)
local sc20 = make_syscall(20)
local sc432 = make_syscall(432)   -- thr_self
local pid = to_num(sc20(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
local tid = 0
do
    local ok, v = pcall(function() return sc432(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then tid = to_num(v) end
end
print(string.format("[0] pid=%d tid=%d", pid, tid))

local function mmap(px)
    local a = to_num(sc477(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a ~= 0 and a < 0x800000000000 then
        for o = 0, px - 4, 4 do safe_wd(a + o, 0) end
    end
    return a
end

local IN = mmap(0x4000)
local DST = mmap(0x4000)
print(string.format("  in=0x%X dst=0x%X", IN, DST))
if IN == 0 or DST == 0 then print("[!] mmap failed"); return end

local CAN = 0xA5A5A5A5
local function fill(a, n, v) for o = 0, n - 4, 4 do safe_wd(a + o, v) end end
local function changed(a, n, v)
    local c = 0
    for o = 0, n - 4, 4 do if safe_rd(a + o) ~= v then c = c + 1 end end
    return c
end

-- key = the +0x08 qword; q0 optionally a mapped page
local function call(tag, key, q0)
    for o = 0, 0x4000 - 8, 8 do safe_wq(IN + o, uint64(0)) end
    if q0 and q0 ~= 0 then safe_wq(IN + 0, uint64(q0)) end
    safe_wq(IN + 8, uint64(key))
    fill(DST, 0x4000, CAN)
    local rv
    local ok = pcall(function() rv = sc601(uint64(0x12), uint64(0), uint64(IN), uint64(0), uint64(0), uint64(0)) end)
    if not ok then print(string.format("  %-24s EXC", tag)) return end
    local e = es()
    local marker = ""
    if e ~= "No such file or directory" then marker = "   <<< NOT ENOENT" end
    print(string.format("  %-24s rv=%-10s errno=%-26s dst_ch=%d%s", tag, sgn(rv), e, changed(DST, 0x100, CAN), marker))
end

print("")
print("[A] process/thread id keys, q0 = 0")
call("key = own pid", pid)
call("key = pid+1", pid + 1)
call("key = own tid", tid)
call("key = 1", 1)
call("key = 2", 2)
call("key = 3", 3)
call("key = 0x64", 0x64)
call("key = 0x191", 0x191)
call("key = 0x100", 0x100)
call("key = pid<<32", pid * 0x100000000)
call("key = (pid<<32)|1", pid * 0x100000000 + 1)

print("")
print("[B] the same keys with qword0 = a mapped destination page")
call("pid, q0=dst", pid, DST)
call("1, q0=dst", 1, DST)
call("2, q0=dst", 2, DST)
call("0x100, q0=dst", 0x100, DST)
call("tid, q0=dst", tid, DST)

print("")
print("[C] key = the two words 0x00 writes (0x100 / 0), and a couple of Sony-ish constants")
call("key = 0x00000100", 0x100)
call("key = 0x50000000", 0x50000000)
call("key = 0x80000000", 0x80000000)

print("")
print("=== 1407a DONE ===")
