-- CRASH_CLASS: LOW
-- PROBE 187a: syscall 94 parked the Lua thread and the capture says it is nosys
--
-- The 10-537 sweep walked 10-93 without trouble, then stopped at 94: two
-- attempts in a row connected, sent, and received nothing, and a PING after
-- that also returned zero bytes while port 9026 kept accepting. That is the
-- parked-thread signature, and only a relaunch clears it.
--
-- The 13.60 capture labels 94 with the shared stub handler (0x265760), the same
-- one 661, 665 and 668 carry, and the sweep's record of those three is a kill,
-- not a park. So one of these is true:
--   a) 14.10 maps 94 somewhere else
--   b) 94 reaches the stub but the stub blocks when the argument registers are
--      zero, which the earlier stubs did not
--   c) the park was an artefact of probing the freshly restarted loader right
--      after 93 killed the previous one
--
-- This probe separates them by calling 94 first, with zero arguments, in a
-- process that has not just died. A BEFORE line prints before the call, so if
-- the loader goes quiet the park is confirmed and the zero-argument shape is
-- the trigger. If the call returns, the same probe walks real fd values and
-- reports each one, which answers (a) and (b).
--
-- Nothing here writes to a buffer the kernel owns. The worst expected outcome is
-- another parked thread, which needs a relaunch, not a power cycle.

print("=== PROBE 187a: SYSCALL 94 ===")
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
local function describe(v)
    local as_str = tostring(v)
    local as_num
    if type(v) == "table" and v.tonumber then
        as_num = v:tonumber()
    else
        as_num = tonumber(v)
    end
    if as_num ~= nil then
        return string.format("%s (%d)", as_str, as_num)
    end
    return string.format("%s (type=%s)", as_str, type(v))
end

local sc94 = make_syscall(94)

-- Section A: the exact shape the sweep used. If this parks, the rest never runs
-- and the capture's last line is the marker below.
print("[A] zero arguments, the shape that parked the sweep")
print("[A] BEFORE")
local ok_a, ret_a = pcall(function()
    return sc94(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("[A] AFTER ok=" .. tostring(ok_a) ..
    " ret=" .. (ok_a and describe(ret_a) or tostring(ret_a)))
print("")

-- Section B: fd values that exist in every process. fd 1 is the loader's own
-- output; if 94 is a sync call it either accepts or rejects them without
-- blocking.
print("[B] single fd argument")
for _, fd in ipairs({1, 2, 0, 3}) do
    print("[B] BEFORE fd=" .. fd)
    local ok, ret = pcall(function()
        return sc94(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print("[B] fd=" .. fd .. " ok=" .. tostring(ok) ..
        " ret=" .. (ok and describe(ret) or tostring(ret)))
end
print("")

-- Section C: a real file descriptor we opened ourselves, so a sync call has
-- something legitimate to work on. fd 5 is the tested `open` number on this
-- firmware; if it fails the section records the fd and moves on.
print("[C] against a descriptor from open(5)")
local path = "/app0/probe187a.tmp"
local sc_open = make_syscall(5)
local opened = -1
repeat
    local ok_open, ret_open = pcall(function()
        return sc_open(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if not ok_open then
        print("[C] open(5) call failed: " .. tostring(ret_open))
        break
    end
    opened = to_num(ret_open)
    print("[C] open(5) returned " .. describe(ret_open))
until true
if opened >= 0 then
    print("[C] BEFORE fd=" .. opened)
    local ok, ret = pcall(function()
        return sc94(uint64(opened), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print("[C] fd=" .. opened .. " ok=" .. tostring(ok) ..
        " ret=" .. (ok and describe(ret) or tostring(ret)))
else
    print("[C] skipped, no descriptor")
end
print("")

-- Section D: the neighbouring numbers, so a park on 94 can be told apart from a
-- park on everything around it.
print("[D] neighbours with the same zero-argument shape")
for _, num in ipairs({92, 93, 95, 96}) do
    local sc = make_syscall(num)
    print("[D] BEFORE " .. num)
    local ok, ret = pcall(function()
        return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print("[D] " .. num .. " ok=" .. tostring(ok) ..
        " ret=" .. (ok and describe(ret) or tostring(ret)))
end

print("")
print("=== PROBE 187a COMPLETE ===")
