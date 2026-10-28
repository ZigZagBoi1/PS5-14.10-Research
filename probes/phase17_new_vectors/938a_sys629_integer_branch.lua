-- CRASH_CLASS: MODERATE
-- PROBE 938a: sys 629 with arg1 == 1 (the branch that skips the name copy and the
--             authority test)
--
-- Context: the 13.60 decompilation in results/kernel_handlers/decompiled/sys_629.c
-- shows two paths:
--     if (uap[0] == 1)  prison = NULL;                      <- no copyinstr, no gate
--     else { copyinstr(uap[0] -> 0x400 buf, max 0x400); require buf[0] == '/';
--            if (authority(cred) && strncmp(buf, "ps4", 3)) -> error 2 }
--     ret = core(proc, prison ? prison : "1", uap[1], (short)uap[2], (int)uap[3], 0)
-- so with uap[0] == 1 the only argument work is integer; nothing user-supplied is
-- dereferenced.  The earlier verdict for 629 ("-1 for every shape") came from probe
-- 54b, whose capture crashed on unrelated kld* retests, so this branch was never
-- cleanly measured.
--
-- This probe walks that branch on a live process and prints the raw returns.  It
-- never passes a pointer as uap[0] from the branch under test, so a bad guess cannot
-- fault on a user address; a kernel-side rejection is the expected result.

print("=== PROBE 938a: SYS 629 arg0=1 BRANCH ===")
print("")

local function to_num(v)
    if type(v) == "table" then
        if v.tonumber then local n = v:tonumber() if n then return n end end
        if v.h then return v.h * 4294967296 + v.l end
    end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local pid = to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
print("[0] pid=" .. tostring(pid))

local function call629(a0, a1, a2, a3)
    local ok, rv = pcall(function() return mk(629)(uint64(a0), uint64(a1), uint64(a2), uint64(a3), uint64(0), uint64(0)) end)
    if not ok then return "PCALL-FAIL" end
    return tostring(to_num(rv))
end

-- uap[0] == 1: the integer branch
for _, jid in ipairs({0, 1, 2, 3, 5, 10}) do
    print(string.format("[A] 629(1,%d,0,0) = %s", jid, call629(1, jid, 0, 0)))
end
print(string.format("[A] 629(1,%d,0,0) = %s  (own pid as jid)", pid, call629(1, pid, 0, 0)))
print(string.format("[A] 629(1,0,1,0) = %s", call629(1, 0, 1, 0)))

-- control: the named branch, with a path that cannot exist
local p = memory.alloc(0x40)
for i = 0, 12 do pcall(function() memory.write_byte(p + i, 0) end) end
pcall(function() memory.write_byte(p, string.byte("/")) end)
pcall(function() memory.write_byte(p + 1, string.byte("x")) end)
print(string.format("[B] 629(name=\"/x\",0,0,0) = %s", call629(to_num(p), 0, 0, 0)))
print(string.format("[B] 629(name=\"/x\",1,0,0) = %s", call629(to_num(p), 1, 0, 0)))

-- 630 is the neighbouring jail-family entry; record it for shape comparison
for _, a0 in ipairs({0, 1}) do
    local ok, rv = pcall(function() return mk(630)(uint64(a0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    print(string.format("[C] 630(%d,0,0,0) = %s", a0, ok and tostring(to_num(rv)) or "PCALL-FAIL"))
end

print(string.format("[Z] alive pid=%s", tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)))))
print("")
print("=== PROBE 938a COMPLETE ===")
