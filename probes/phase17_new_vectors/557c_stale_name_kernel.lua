-- CRASH_CLASS: HIGH
-- PROBE 557c: does the kernel read a stale name pointer? (no userland read)
--
-- 557b died after `munmap(p) ret=0`, but its next statement was the probe's own
-- `memory.read_byte(p)` - a userland read of the page just unmapped, which this
-- loader cannot survive (the same way an XO page read is fatal past pcall).
-- That death therefore says nothing about the kernel.
--
-- This version never touches p again after the unmap. If the process dies at
-- step 3 instead, the dereference is the kernel's: a second 557 with the same
-- name would be walking a name table and comparing against the stale pointer.
--
-- If it survives, 557 copies the string (or never compares) and the object
-- holds no user pointer.

print("=== PROBE 557c: stale name pointer, kernel side ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function call(f,...)
    local ok,rv=pcall(f,...)
    if not ok then return -999 end
    return to_num(rv)
end
local function mmap(px)
    local _, a = pcall(function()
        return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end
local function str_at(addr, s)
    for i = 1, #s do wb(addr + i - 1, string.byte(s, i)) end
    wb(addr + #s, 0)
end

print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))

local PAGE = 0x4000
local p = mmap(PAGE)
if p == 0 then print("[!] mmap p failed"); return end
str_at(p, "uafname557c")
local h1 = call(mk(557), uint64(p), uint64(0), uint64(0), uint64(0))
print(string.format("[1] p=%X create ret=%d (0x%X)", p, h1, h1 % 4294967296))
if h1 <= 0 then print("[!] create failed"); return end

print("[2] munmap(p) ret=" .. call(mk(73), uint64(p), uint64(PAGE)))
print("    (p is never read again from userland)")

-- a fresh page, freed by a different mmap landing elsewhere
local q = mmap(PAGE)
if q == 0 then print("[!] mmap q failed"); return end
str_at(q, "uafname557c")
print(string.format("[3] q=%X, creating a second object with the same name", q))
local h2 = call(mk(557), uint64(q), uint64(0), uint64(0), uint64(0))
print(string.format("[3] second create ret=%d (0x%X) alive=%d", h2, h2 % 4294967296,
    to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))

print("[4] delete h1=" .. h1 .. " ret=" .. call(mk(558), uint64(h1)))
print("[4] delete h2=" .. h2 .. " ret=" .. call(mk(558), uint64(h2)))
print("[Z] alive=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== PROBE 557c COMPLETE ===")
