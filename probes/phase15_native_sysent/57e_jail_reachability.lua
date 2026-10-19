-- CRASH_CLASS: MODERATE
-- PROBE 57e: jail syscall reachability (gates 1-2 for CVE-2026-49419)
--
-- Context: no probe or capture in the repo ever issues jail(338),
-- jail_attach(429), jail_get(496), or jail_set(497), and in the 13.60 dumps
-- 338/496/497 sit at the nosys slot. This probe does NOT attempt the
-- double-release. It answers the prior question: does a handler exist behind
-- each number? See docs/CVE-2026-49419-PS5-14.10.md.
--
-- Each call is isolated with BEFORE/RETURNED markers so a crash inside one
-- call is distinguishable from a capture that never reached it.

print("=== PROBE 57e: JAIL SYSCALL REACHABILITY ===")
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

local function tag_call(name, num, a1, a2, a3, a4, a5, a6)
    print("  [BEFORE] " .. name)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1), uint64(a2), uint64(a3),
            uint64(a4), uint64(a5), uint64(a6))
    end)
    if ok then
        print(string.format("  [RETURNED] %s rv=%s", name, tostring(rv)))
        return true, to_num(rv)
    end
    print(string.format("  [RAISED] %s err=%s", name, tostring(rv)))
    return false, -999
end

-- Upstream numbers (sys/kern/syscalls.master, stable/14):
--   338 jail(struct jail *)
--   429 jail_attach(int jid)
--   496 jail_get(struct uio *, unsigned flags)
--   497 jail_set(struct uio *, unsigned flags)

print("--- A: legacy jail(338) ---")
local jp = memory.alloc(64)
for i = 0, 63 do
    pcall(function() memory.write_byte(jp + i, 0) end)
end
tag_call("jail(338) zeroed-struct", 338, jp, 0, 0, 0, 0, 0)

print("")
print("--- B: jail_attach(429) ---")
-- jid 0 and -1 are both invalid; a structured refusal proves dispatch works.
tag_call("jail_attach(429) jid=0", 429, 0, 0, 0, 0, 0, 0)
tag_call("jail_attach(429) jid=-1", 429, 0xFFFFFFFF, 0, 0, 0, 0, 0)

print("")
print("--- C: jail_get(496) ---")
local iov = memory.alloc(64)
for i = 0, 63 do
    pcall(function() memory.write_byte(iov + i, 0) end)
end
-- flags=0 first: no descriptor involved, maps the base handler.
tag_call("jail_get(496) flags=0", 496, iov, 0, 0, 0, 0, 0)

print("")
print("--- D: jail_set(497) ---")
-- flags=0 with an empty uio: must not create anything, only maps dispatch.
tag_call("jail_set(497) flags=0", 497, iov, 0, 0, 0, 0, 0)

print("")
print("=== PROBE 57e COMPLETE ===")
