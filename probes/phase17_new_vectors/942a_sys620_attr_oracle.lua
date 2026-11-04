-- CRASH_CLASS: MODERATE
-- PROBE 942a: does sys 620 change the protection of the page we return to?
--
-- Context: the 13.60 body of sys 620 (0xffffffff8b47d430) takes the saved RIP
-- from td->trapframe+0x100, aligns (rip-0x80) down to 16 KB, looks the VM entry
-- up, and calls 0x8ae23610(map, entry_start>>14, page_index, mode=5).  Mode 5
-- with a page count is an attribute change, not a mapping change, so the sys 624
-- counter we watched in 99b would not move either way - that measurement did
-- not actually test whether the attribute change happened.
--
-- sys 547 reports the VM entry's protection word, so the question is decidable:
-- query the entry that contains the return address, call 620, query it again.
--
-- A: protection of the page containing syscall.pipe.fn_addr (the stub we return into)
-- B: the same page for a Lua C function (memory.alloc) and for the loader text
-- C: call 620, query all three again, print the delta
-- D: call 620 five more times, query again
--
-- Nothing is written to any page; only 547 and 620 are used.

print("=== PROBE 942a: SYS 620 ATTRIBUTE-CHANGE ORACLE ===")
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
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end return nil end
local function rq(a) local o, v = pcall(function() return memory.read_qword(a) end); if o then return v end return nil end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function call(f, ...)
    local ok, rv = pcall(f, ...)
    if not ok then return "PCALL-FAIL" end
    return to_num(rv)
end

local sc547, sc620 = mk(547), mk(620)
local out = memory.alloc(0x40)

local function query(tag, addr)
    if type(addr) ~= "number" or addr <= 0 then print(string.format("[%s] no address", tag)); return nil end
    for i = 0, 0xF do wd(out + i * 4, 0xDEAD0000 + i) end
    local r = call(function() return sc547(uint64(addr), uint64(out)) end)
    if r == 0 then
        local prot = rd(out + 0x10) or 0
        print(string.format("[%s] 0x%X  start=%s end=%s prot=0x%X flags=0x%X", tag, addr,
            tostring(rq(out)), tostring(rq(out + 8)), prot, rd(out + 0x14) or 0))
        return prot
    end
    print(string.format("[%s] 0x%X ret=%s", tag, addr, tostring(r)))
    return nil
end

print("[0] pid=" .. tostring(call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)))

local fn = to_num(syscall.pipe.fn_addr)
local lua_fn = to_num(memory.alloc)
print(string.format("[0] fn_addr=0x%X memory.alloc=%s", fn, tostring(memory.alloc)))

print("[A] before")
local p1 = query("A fn", fn)
local p2 = query("B alloc", lua_fn)

print("[C] calling sys 620 once")
print("   ret=" .. tostring(call(function() return sc620() end)))
local q1 = query("A fn", fn)
local q2 = query("B alloc", lua_fn)

print("[D] five more calls")
for i = 1, 5 do call(function() return sc620() end) end
local r1 = query("A fn", fn)
local r2 = query("B alloc", lua_fn)

print("")
print(string.format("[Z] fn prot: 0x%X -> 0x%X -> 0x%X", p1 or 0, q1 or 0, r1 or 0))
print(string.format("[Z] alloc prot: 0x%X -> 0x%X -> 0x%X", p2 or 0, q2 or 0, r2 or 0))

print("")
print("=== PROBE 942a COMPLETE ===")
