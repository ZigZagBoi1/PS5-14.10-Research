-- CRASH_CLASS: LOW
-- PROBE 193a: what the created handles do
--
-- Context: 192a found that 538 and 557 accept a non-null first argument and
-- return small sequential handles (518..536 in pid 94), and that 539/558
-- delete them (0 on first delete, -1 on the second). The ABI is now known for
-- create and delete; nothing is known about the calls that consume a handle.
--
-- This probe takes one handle through the evf calls: trywait on an unset flag,
-- set it, trywait twice (does the wait clear the bit or not), wait with the bit
-- already set, open the same name from the table, close the handle and then use
-- it anyway. The close-then-use step is the point: a handler that does not
-- revalidate a closed handle is a use-after-free candidate.

print("=== PROBE 193a: handle lifecycle ===")
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
local function u64(v)
    if type(v) == "number" then return uint64(string.format("0x%08X", v)) end
    return v
end
local function show(v)
    if v == nil then return "killed" end
    return tostring(v)
end
local dead = false

local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(u64(a1 or 0), u64(a2 or 0), u64(a3 or 0), u64(a4 or 0), u64(a5 or 0), u64(a6 or 0))
    end)
    if not ok then
        dead = true
        return nil, nil
    end
    return ret, to_num(ret)
end

local NAME = memory.alloc(0x40)
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, u64(string.byte(s, i))) end)
    end
    pcall(function() memory.write_byte(addr + #s, u64(0)) end)
end
put_str(NAME, "evf_a_193a")

local _, pid = call(20)
print("[0] getpid " .. show(pid))
print("")

-- ============================================================
-- A: create one event flag and look at every evf call
-- ============================================================
print("[A] evf create/trywait/set/wait/close/delete")

local _, A = call(538, NAME, 0, 0)
print("    create(NAME,0,0)      -> " .. show(A))
if dead or A == nil or A < 0 then
    print("    create failed; stopping")
    print("=== PROBE 193a COMPLETE ===")
    return
end

local function step(label, num, ...)
    if dead then return nil end
    local _, rv = call(num, ...)
    print(string.format("    %-28s -> %s", label, show(rv)))
    return rv
end

step("trywait(A, 0x1)", 543, A, 0x1)
step("set(A, 0x1)", 544, A, 0x1)
step("trywait(A, 0x1)", 543, A, 0x1)
step("trywait(A, 0x1)", 543, A, 0x1)
step("wait(A, 0x1, 0)", 542, A, 0x1, 0)
step("set(A, 0x2)", 544, A, 0x2)
step("wait(A, 0x2, 0)", 542, A, 0x2, 0)
step("open(NAME)", 540, NAME)
step("close(A)", 541, A)
step("trywait(A, 0x1) after close", 543, A, 0x1)
step("set(A, 0x4) after close", 544, A, 0x4)
step("delete(A) after close", 539, A)
step("trywait(A, 0x1) after delete", 543, A, 0x1)
print("")

-- ============================================================
-- B: two creates with the same name
-- ============================================================
print("[B] same name twice")
local _, B1 = call(538, NAME, 0, 0)
local _, B2 = call(538, NAME, 0, 0)
print("    create -> " .. show(B1) .. ", create again -> " .. show(B2))
if not dead then
    print("    same handle: " .. tostring(B1 == B2))
    call(539, B1)
    call(539, B2)
end
print("")

-- ============================================================
-- C: named object around a create/delete cycle
-- ============================================================
print("[C] namedobj create/delete")
put_str(NAME, "nobj_193a")
local _, C1 = call(557, NAME, 0, 0)
print("    create(NAME,0,0)      -> " .. show(C1))
if not dead and C1 and C1 >= 0 then
    print("    delete(C1)            -> " .. show((call(558, C1))))
    print("    delete(C1) again      -> " .. show((call(558, C1))))
end
print("")

print("=== PROBE 193a COMPLETE ===")
