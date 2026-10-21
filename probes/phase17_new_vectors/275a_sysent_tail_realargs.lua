-- CRASH_CLASS: HIGH (677+ killed every zero-args caller on 14.10; game crashed on 677/678)
-- PROBE 275a: real-args discrimination for the 677+ kill range
--
-- Context: the 14.10 isolation sweep killed on all of 677-707 with six zero
-- arguments. The 13.60 sysent names CSV (docs/sysent-names-13.60.csv) lists
-- 735 entries, and the recovered kernel text resolves every 677-734 thunk:
-- 53 real handlers (wait6 677, cap_* 678-682, bindat 683 ... pipe2 687,
-- ppoll 690, numa_* 693/694, apr_* 700-704, get_phys_page_size 705 ...),
-- only 695-699 are nosys. So "past-the-end" is not the only reading of the
-- 14.10 kills: the handlers may exist and fault on zeros.
--
-- This probe calls the members of that range whose implementations cannot
-- fault on any argument (pure reads or fully user-supplied buffers), ordered
-- safest first:
--   705 get_phys_page_size()   -> expect 0x4000 if present
--   713 get_ppr_sdk_compiled_version() -> constant
--   733 get_resident_fmem_count2(&buf) -> count write
--   687 pipe2(&fds, 0)         -> two fds
--   690 ppoll(&fds, 0, 0, 0)   -> 0
-- A kill on 705 (a zero-arg read) would be the strongest "table ends before
-- 705" signal available; a return value proves the table extends there.

print("=== PROBE 275a: real-args discrimination for 677+ ===")
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
local function raw(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    return "0x" .. string.format("%X", to_num(v))
end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(addr, n)
    for off = 0, n - 1, 8 do wq(addr + off, uint64(0)) end
end

local function try(num, label, args)
    local sc = make_syscall(num)
    local a = args or {}
    local ok, rv = pcall(function()
        return sc(a[1] or uint64(0), a[2] or uint64(0), a[3] or uint64(0),
                  a[4] or uint64(0), a[5] or uint64(0), a[6] or uint64(0))
    end)
    print(string.format("    %-6d %-28s ok=%s ret=%s", num, label, tostring(ok), raw(rv)))
    return ok, rv
end

print("[A] pure-read members of the kill range")
try(705, "get_phys_page_size")
try(713, "get_ppr_sdk_version")

print("")
print("[B] buffer-taking members, valid buffers")
local buf = memory.alloc(0x100)
zero(buf, 0x100)
try(733, "get_resident_fmem_count2", { uint64(0), uint64(buf) })
print("    buf[0] after 733: " .. tostring(rq(buf) ~= nil and raw(rq(buf)) or "unreadable"))

zero(buf, 0x100)
try(687, "pipe2", { uint64(buf), uint64(0) })
local p0, p1 = rq(buf), rq(buf + 8)
print("    fds: " .. (p0 ~= nil and raw(p0) or "?") .. " " .. (p1 ~= nil and raw(p1) or "?"))
if p0 ~= nil and to_num(p0) >= 0 then pcall(function() make_syscall(6)(p0) end) end
if p1 ~= nil and to_num(p1) >= 0 then pcall(function() make_syscall(6)(p1) end) end

zero(buf, 0x100)
try(690, "ppoll(nfds=0)", { uint64(buf), uint64(0), uint64(0), uint64(0) })

print("")
local ok, pid = pcall(function() return make_syscall(20)():tonumber() end)
print("[C] canary: ok=" .. tostring(ok) .. " pid=" .. tostring(pid))
print("=== END 275a ===")
