-- CRASH_CLASS: LOW
-- PROBE 486b: do 668 (aio_create) and 661 (aio_submit) still answer ENOSYS on 14.10?
--
-- On 13.60 both handlers funnel into 0x5620e0 with the user pointer discarded,
-- build {type=0xc, code=0x10006} and return 0x4e (ENOSYS).
-- 662's body turned out to be reachable on 14.10, so re-check the create path:
-- any return other than 0x4e means the service exists and objects may be made.

print("=== PROBE 486b: aio create/submit service ===")
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
local function sgn(v)
    local n = to_num(v)
    if n >= 0x8000000000000000 then return n - 0x10000000000000000 end
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local buf = memory.alloc(0x1000)
for i = 0, 0xFFF, 4 do wd(buf + i, 0) end

local function call(num, a, b, c, label)
    local sc = make_syscall(num)
    local ok, rv = pcall(function() return sc(uint64(a), uint64(b), uint64(c)) end)
    local r = ok and sgn(rv) or -999
    print(string.format("  [%s] sys%d(%#x,%#x,%#x) ret=%d", label, num, a, b, c, r))
end

print("[A] create 668 with several shapes")
call(668, buf, 0x100, 0x10, "A1")
call(668, buf, 0x10, 0, "A2")
call(668, 0, 0, 0, "A3")
call(668, buf, 0x100, 0, "A4")

print("[B] submit 661 with several shapes")
call(661, buf, 1, 0, "B1")
call(661, buf, 0x10, 0, "B2")
call(661, 0, 0, 0, "B3")

print("[C] wait/poll with a freshly zeroed id array")
local ids = memory.alloc(0x1000)
for i = 0, 0xFFF, 4 do wd(ids + i, 0x41424344) end
call(663, ids, 1, buf, "C1")
call(664, ids, 1, buf, "C2")

print("=== PROBE 486b END ===")
