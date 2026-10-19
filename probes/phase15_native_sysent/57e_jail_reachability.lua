-- CRASH_CLASS: LOW
-- PROBE 57e: jail syscall reachability (gates 1-2 for CVE-2026-49419)
--
-- CORRECTION (2026-10-19): the first version of this probe used 429 for
-- jail_attach and 496/497 for jail_get/jail_set, taken from a stale label
-- table. The committed 13.60 capture says otherwise: 429 is sigwait, 496 is
-- mkdirat, 497 is mkfifoat, and no slot in either the native or the compat
-- table carries a jail name. The jail candidates are 338 (jail), 436
-- (jail_attach), 506 (jail_get) and 507 (jail_set), and all four are
-- unimplemented slots pointing at nosys (0x265760) in 13.60.
--
-- What this probe measures on 14.10: whether any of those four numbers has a
-- real handler. A nosys slot returns -1 (ENOSYS) for every argument shape; a
-- real handler returns something structured or crashes. This does NOT attempt
-- the double-release from CVE-2026-49419; see docs/CVE-2026-49419-PS5-14.10.md.
--
-- Numbers are stable across FreeBSD 9-era numbering; 13.60 evidence is context
-- for 14.10, not proof about it.

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

print("--- A: jail(338) ---")
local jp = memory.alloc(64)
for i = 0, 63 do
    pcall(function() memory.write_byte(jp + i, 0) end)
end
-- FreeBSD 9 signature: jail(struct jail *jail). Zeroed struct cannot create.
tag_call("jail(338) zeroed", 338, jp, 0, 0, 0, 0, 0)

print("")
print("--- B: jail_attach(436) ---")
-- jid 0 and -1 are both invalid; a structured refusal proves dispatch works.
tag_call("jail_attach(436) jid=0", 436, 0, 0, 0, 0, 0, 0)
tag_call("jail_attach(436) jid=-1", 436, 0xFFFFFFFF, 0, 0, 0, 0, 0)

print("")
print("--- C: jail_get(506) ---")
-- FreeBSD 9 signature: jail_get(struct iov *iov, unsigned flags).
-- flags=0 cannot create anything.
local iov = memory.alloc(64)
for i = 0, 63 do
    pcall(function() memory.write_byte(iov + i, 0) end)
end
tag_call("jail_get(506) flags=0", 506, iov, 0, 0, 0, 0, 0)

print("")
print("--- D: jail_set(507) ---")
tag_call("jail_set(507) flags=0", 507, iov, 0, 0, 0, 0, 0)

print("")
print("--- E: control, sigwait(429) ---")
-- 429 is sigwait, not jail_attach. A structured errno here (rather than a
-- thread block) confirms the number is dispatched as sigwait on this firmware.
tag_call("sigwait(429) null set", 429, 0, 0, 0, 0, 0, 0)

print("")
print("=== PROBE 57e COMPLETE ===")
