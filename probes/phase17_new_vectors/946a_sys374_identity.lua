-- CRASH_CLASS: HIGH
-- PROBE 946a: what is syscall 374 on 14.10?
--
-- Context: 945a died on its FIRST shape, 374(path, NULL, 0, 0) - no buffer, no
-- length - so 944a's kill was not the copyout path.  Whatever 374 is on 14.10,
-- it is fatal before it touches a destination buffer.
--
-- Two remaining explanations:
--   1. the number has no entry (or a lethal gate), the same shape as kldstat;
--   2. the handler dereferences its first argument directly, and a Lua string
--      pointer (or NULL) faults.
-- A bare call with zero arguments separates them: a missing number dies before
-- the arguments matter, a direct dereference of garbage may or may not.
--
-- Shapes run in increasing danger, with a canary and a poison re-read after each:
--   A  374()                     no arguments at all
--   B  374(P, 0, 0, 0)           mapped, zeroed page as argument 1
--   C  374(0, P, 0, 0)           mapped page as argument 2
--   D  374(P, P, 0, 0)           both
--   E  374(P, P, 0x100, 0)       both plus a length
-- P is poisoned with 0xA5A5A5A5 first, so a kernel write into it is visible.

print("=== PROBE 946a: SYS 374 IDENTITY ===")
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
local function call(f, ...)
    local ok, rv = pcall(f, ...)
    if not ok then return nil end
    return to_num(rv)
end

local pid = call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
print("[0] pid=" .. tostring(pid))

local P = call(function() return make_syscall(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
print("[0] page P=0x" .. string.format("%X", P or 0))
if not P or P <= 0 then print("[!] no page"); return end
for i = 0, 0x3F do pcall(function() memory.write_dword(P + i * 4, 0xA5A5A5A5) end) end

local sc374 = mk(374)
local function probe(tag, fn)
    local ret = call(fn)
    print(string.format("  %-24s ret=%s", tag, tostring(ret)))
    local d = nil
    local ok, v = pcall(function() return memory.read_dword(P) end)
    if ok then d = to_num(v) end
    print(string.format("     P[0]=0x%08X (poison 0xA5A5A5A5)", d or 0))
    local p2 = call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
    if p2 ~= pid then print(string.format("[!] DEAD after %s", tag)) return false end
    return true
end

if not probe("374()", function() return sc374() end) then return end
if not probe("374(P,0,0,0)", function() return sc374(uint64(P), uint64(0), uint64(0), uint64(0)) end) then return end
if not probe("374(0,P,0,0)", function() return sc374(uint64(0), uint64(P), uint64(0), uint64(0)) end) then return end
if not probe("374(P,P,0,0)", function() return sc374(uint64(P), uint64(P), uint64(0), uint64(0)) end) then return end
if not probe("374(P,P,0x100,0)", function() return sc374(uint64(P), uint64(P), uint64(0x100), uint64(0)) end) then return end

print("")
print("[Z] survived every shape - 374 is argument-driven, not lethal at touch")
print("=== PROBE 946a COMPLETE ===")
