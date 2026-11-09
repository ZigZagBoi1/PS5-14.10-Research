-- CRASH_CLASS: HIGH
-- PROBE 591a: retest the gated syscalls after all chicken switches are set
--
-- 643 writes "or dword [proc+0xa34], arg1" (13.60 body 0xffffffff8b3f7660), so it
-- sets arbitrary bits in the per-process chicken-switch word.  Probe 55a set
-- 0xFFFFFFFF and only rechecked mprotect/fork/kldstat.  This probe rechecks the
-- syscalls that refuse for other reasons: 676, 672, 673, 601 cmd 0x27, 648, 646.
-- 601 cmd 3 killed the game before, so it runs last.

print("=== PROBE 591a: CHICKEN GATE RETEST ===")

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
local function u64(v) return uint64(tostring(v)) end
local function hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, to_num(v)
end
local function hex64(v)
    local h, l = hi_lo(v)
    return string.format("%08X_%08X", to_num(h), to_num(l))
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local sc643 = make_syscall(643)
local sc676 = make_syscall(676)
local sc672 = make_syscall(672)
local sc673 = make_syscall(673)
local sc648 = make_syscall(648)
local sc646 = make_syscall(646)
local sc601 = make_syscall(601)
local sc629 = make_syscall(629)

local ok, r = pcall(function() return sc643(u64(0xFFFFFFFF)) end)
print("[A] set_chicken_switches(0xFFFFFFFF) ok=" .. tostring(ok) .. " ret=" .. (ok and hex64(r) or tostring(r)))
local ok2, r2 = pcall(function() return sc643(u64(0xFFFFFFFF)) end)
print("[A] second call ok=" .. tostring(ok2) .. " ret=" .. (ok2 and hex64(r2) or tostring(r2)))

local buf = memory.alloc(0x1000)
for i = 0, 0xFF do wd(buf + i * 4, 0) end

local function call(tag, fn)
    local k, v = pcall(fn)
    print(string.format("[B] %s ok=%s ret=%s", tag, tostring(k), k and hex64(v) or tostring(v)))
    return k, v
end

call("676(0,0)", function() return sc676(0, 0, 0, 0, 0, 0) end)
call("676(1,0)", function() return sc676(1, 0, 0, 0, 0, 0) end)
call("672(buf,0x100,0)", function() return sc672(u64(buf), 0x100, 0, 0, 0, 0) end)
call("673(0,0,0)", function() return sc673(0, 0, 0, 0, 0, 0) end)
call("648(0,0)", function() return sc648(0, 0, 0, 0, 0, 0) end)
call("646(buf,0x100)", function() return sc646(u64(buf), 0x100, 0, 0, 0, 0) end)
call("629(0)", function() return sc629(0, 0, 0, 0, 0, 0) end)
print("[C] buf[0]=" .. string.format("%08X", rd(buf)))

call("601(0x27,buf)", function() return sc601(0x27, u64(buf), 0, 0, 0, 0) end)
print("[D] 601 alive after 0x27")
call("601(3,buf)", function() return sc601(3, u64(buf), 0, 0, 0, 0) end)
print("[E] alive after 601(3)")
