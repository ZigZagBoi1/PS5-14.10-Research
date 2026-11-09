-- CRASH_CLASS: LOW
-- PROBE 157b: why did the context readback show zeros?
--
-- 157a observed the child loop (timeval advanced) but rq(ctx+0x0E0) printed
-- 0x0 and rq(tid_buf) printed 0x0. Either the reads failed or the values are
-- not what q() expects. This probe checks read_qword/read_dword return shapes
-- on memory.alloc buffers and prints raw types.

print("=== PROBE 157b: MEMORY READBACK SHAPE ===")
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

local buf = memory.alloc(0x500)
print("[0] buf type=" .. type(buf) .. " tostring=" .. tostring(buf))

local ok_w = pcall(function() memory.write_qword(buf + 0x0E0, uint64(0x1122334455667788)) end)
print("[0] write_qword at +0x0E0 ok=" .. tostring(ok_w))

local ok_r, a, b = pcall(function() return memory.read_qword(buf + 0x0E0) end)
print("[0] read_qword: ok=" .. tostring(ok_r) .. " a_type=" .. type(a) ..
    " a=" .. tostring(a) .. " b_type=" .. type(b) .. " b=" .. tostring(b))

local ok_r2, c = pcall(function() return memory.read_qword(buf + 0x0E0) end)
print("[0] two-value capture: ok=" .. tostring(ok_r2) .. " c=" .. tostring(c))

local ok_d, d = pcall(function() return memory.read_dword(buf + 0x0E0) end)
print("[0] read_dword at +0x0E0: ok=" .. tostring(ok_d) .. " type=" .. type(d) ..
    " val=" .. tostring(d))

local ok_d2, e = pcall(function() return memory.read_dword(buf + 0x0E4) end)
print("[0] read_dword at +0x0E4: ok=" .. tostring(ok_d2) .. " val=" .. tostring(e))

-- Same read with an explicit uint64 address
local addr = uint64(string.format("0x%X", to_num(buf))) + 0x0E0
local ok_u, f = pcall(function() return memory.read_qword(addr) end)
print("[0] read_qword via uint64 addr: ok=" .. tostring(ok_u) .. " type=" .. type(f) ..
    " val=" .. tostring(f))

-- thr_self
local sc_thr_self = make_syscall(432)
local tb = memory.alloc(8)
pcall(function() memory.write_qword(tb, uint64(0)) end)
local ok_s = pcall(function() sc_thr_self(uint64(tb)) end)
local ok_sr, sv = pcall(function() return memory.read_qword(tb) end)
print("[0] thr_self ok=" .. tostring(ok_s) .. " read ok=" .. tostring(ok_sr) ..
    " val=" .. tostring(sv) .. " type=" .. type(sv))

local sc_getpid = make_syscall(20)
local ok_pid, pid = pcall(function() return sc_getpid():tonumber() end)
print("[1] canary pid=" .. tostring(pid))

print("")
print("=== PROBE 157b COMPLETE ===")
