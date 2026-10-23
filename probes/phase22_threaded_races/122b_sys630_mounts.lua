-- CRASH_CLASS: LOW
-- PROBE 122b: sys 630 mount enumeration (no privilege needed per 13.60 RE)
--
-- 13.60 analysis: sys 630 has multiple subcmds behind its first arg.
-- When arg0 is a path pointer and succeeds, it's a mount operation.
-- But the enumeration functions at offsets 0x0d0, 0x1f0, 0x310, 0x7a0
-- need NO privilege at all.
--
-- Also test: cross-process mount lookup by PID (offset 0x450).
-- This probe tests sys 630 with various argument shapes to find
-- which subcmds are reachable.

print("=== PROBE 122b: SYS 630 MOUNT ENUM ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function wb(addr, b) pcall(function() memory.write_byte(addr, b) end) end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc630 = mk(630)
local buf = memory.alloc(0x2000)
local BUF = N(buf)

local function put_str(s, off)
    off = off or 0
    for i = 1, #s do wb(BUF + off + i - 1, string.byte(s, i)) end
    wb(BUF + off + #s, 0)
    return uint64(BUF + off)
end

-- Zero output area
for i = 0, 0x7FF, 4 do wd(BUF + 0x800 + i, 0) end
local outbuf = uint64(BUF + 0x800)

-- [A] Basic arg0 sweep: sentinel values 0-10 + powers
print("[A] arg0 small values")
for _, a0 in ipairs({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) do
    for i = 0, 0x7F, 4 do wd(BUF + 0x800 + i, 0) end
    local ok, rv = pcall(function()
        return sc630(uint64(a0), outbuf, uint64(0x400), uint64(0))
    end)
    local ret = ok and sgn(rv) or "PFAIL"
    local w0 = rd(BUF + 0x800)
    local w4 = rd(BUF + 0x804)
    if w0 == nil then w0 = 0 end
    if w4 == nil then w4 = 0 end
    if w0 < 0 then w0 = w0 + 0x100000000 end
    if w4 < 0 then w4 = w4 + 0x100000000 end
    local tag = ""
    if w0 ~= 0 or w4 ~= 0 then
        tag = string.format(" [0]=%08X [4]=%08X", w0, w4)
    end
    print(string.format("  630(%d, outbuf, 0x400, 0) -> %s%s", a0, tostring(ret), tag))
end

local c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [B] Try path strings (mount operation paths)
print("")
print("[B] path pointer calls")
for _, p in ipairs({"/", "/dev", "/system", "/app0", "/data"}) do
    local ptr = put_str(p)
    local ok, rv = pcall(function() return sc630(ptr, uint64(0), uint64(0), uint64(0)) end)
    print(string.format("  630(\"%s\") -> %s", p, ok and tostring(sgn(rv)) or "PFAIL"))
end

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [C] Cross-process mount lookup by PID
-- The function at offset 0x450 takes PID
print("")
print("[C] cross-process lookup by PID")
for _, test_pid in ipairs({pid, 1, 0, 2, 100}) do
    for i = 0, 0x7F, 4 do wd(BUF + 0x800 + i, 0) end
    local ok, rv = pcall(function()
        return sc630(uint64(test_pid), outbuf, uint64(0x400), uint64(0))
    end)
    local ret = ok and sgn(rv) or "PFAIL"
    local w0 = rd(BUF + 0x800)
    if w0 ~= nil and w0 < 0 then w0 = w0 + 0x100000000 end
    print(string.format("  630(pid=%d) -> %s [0]=%s", test_pid, tostring(ret),
        w0 ~= nil and string.format("%08X", w0) or "nil"))
end

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [D] Try with different arg layouts (narg=1 means only first arg used by entry)
-- But subcmds may read further args from td_frame
print("")
print("[D] sentinel=1 (same as physhm_open uses)")
local ok4, rv4 = pcall(function() return sc630(uint64(1), uint64(0), uint64(0), uint64(0)) end)
print("  630(1,0,0,0) -> " .. (ok4 and tostring(sgn(rv4)) or "PFAIL"))

print("")
c = N(native.fcall_with_rax(stub, 20))
print(string.format("canary=%s", c == pid and "OK" or "FAIL"))
print("=== 122b COMPLETE ===")
