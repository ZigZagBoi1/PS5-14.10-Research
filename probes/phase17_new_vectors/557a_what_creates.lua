-- CRASH_CLASS: LOW
-- PROBE 557a: what syscall 557 actually creates, and what deletes it
--
-- History: 46a/47a treated the first argument of 557 as a "version" and swept
-- 0..255, recording returns like 0x4205, 0x206, 0x304. Those are not version
-- outputs - they are handle-shaped, the same numbering 88b measured for event
-- flags (525, 526) and generic objects (529), where the handle is the return
-- value and the generation sits in the high bits (0x220F = slot 0x20F, gen 2).
--
-- 88b called 557(name_ptr, 0, 0, 0) and got a handle back (529). So 557 is a
-- creator; this probe pins down which argument is the name, which is a type or
-- flags, and then finds the call that deletes the object it made.

print("=== PROBE 557a: 557 creates what, and who deletes it ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function nm(s)
    local b=memory.alloc(0x40); zero(b,0x40)
    for i=1,#s do pcall(function() memory.write_byte(b+i-1,string.byte(s,i)) end) end
    return b
end
local function call(f,...)
    local ok,rv=pcall(f,...)
    if not ok then return -999 end
    return to_num(rv)
end
local function tag(label, f)
    local r = call(f)
    print(string.format("  %-34s ret=%d (0x%X)", label, r, r % 4294967296))
    return r
end

print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))

local st = memory.alloc(0x200)   -- a zeroed struct for the buffer-shaped calls
local name = nm("n557a")

--------------------------------------------------------------------
-- 1: confirm the numbering against a known family
--------------------------------------------------------------------
print("--- 1: handle numbering ---")
local ef = tag("538 create", function() return mk(538)(uint64(nm("ef557a")), uint64(0), uint64(0), uint64(0)) end)
local sem = tag("549 create", function() return mk(549)(uint64(nm("se557a")), uint64(0), uint64(1), uint64(0x1000)) end)
tag("539 delete ef", function() return mk(539)(uint64(ef)) end)
print("")

--------------------------------------------------------------------
-- 2: 557 argument shapes
--------------------------------------------------------------------
print("--- 2: 557 shapes ---")
local h = {}
h[1] = tag("557(name,0,0,0)",       function() return mk(557)(uint64(name), uint64(0), uint64(0), uint64(0)) end)
h[2] = tag("557(struct,0,0,0)",     function() return mk(557)(uint64(st), uint64(0), uint64(0), uint64(0)) end)
h[3] = tag("557(0,struct,0,0)",     function() return mk(557)(uint64(0), uint64(st), uint64(0), uint64(0)) end)
h[4] = tag("557(0,0,struct,0)",     function() return mk(557)(uint64(0), uint64(0), uint64(st), uint64(0)) end)
h[5] = tag("557(name,0x1000,0,0)",  function() return mk(557)(uint64(name), uint64(0x1000), uint64(0), uint64(0)) end)
h[6] = tag("557(name,1,0,0)",       function() return mk(557)(uint64(name), uint64(1), uint64(0), uint64(0)) end)
print("")

--------------------------------------------------------------------
-- 3: which argument is a name?  two objects, same name
--------------------------------------------------------------------
print("--- 3: same name twice ---")
local n2 = nm("same557")
local x1 = tag("557(nameA)", function() return mk(557)(uint64(n2), uint64(0), uint64(0), uint64(0)) end)
local x2 = tag("557(nameA again)", function() return mk(557)(uint64(n2), uint64(0), uint64(0), uint64(0)) end)
print("")

--------------------------------------------------------------------
-- 4: delete shapes for a handle 557 returned
--------------------------------------------------------------------
print("--- 4: who deletes handle " .. h[1] .. " ---")
if h[1] > 0 then
    tag("558(h)",            function() return mk(558)(uint64(h[1])) end)
    tag("558(h,0)",          function() return mk(558)(uint64(h[1]), uint64(0)) end)
    tag("558(h,1)",          function() return mk(558)(uint64(h[1]), uint64(1)) end)
    tag("558(0,h)",          function() return mk(558)(uint64(0), uint64(h[1])) end)
    tag("558(h,0x1000)",     function() return mk(558)(uint64(h[1]), uint64(0x1000)) end)
    tag("558(0x1000,h)",     function() return mk(558)(uint64(0x1000), uint64(h[1])) end)
    tag("558(name,h)",       function() return mk(558)(uint64(name), uint64(h[1])) end)
    tag("558(h,name)",       function() return mk(558)(uint64(h[1]), uint64(name)) end)
    tag("558(h,st)",         function() return mk(558)(uint64(h[1]), uint64(st)) end)
    tag("558(h,0,0,0)",      function() return mk(558)(uint64(h[1]), uint64(0), uint64(0), uint64(0)) end)
    tag("550(h)",            function() return mk(550)(uint64(h[1])) end)
    tag("552(h)",            function() return mk(552)(uint64(h[1])) end)
    tag("539(h)",            function() return mk(539)(uint64(h[1])) end)
end
print("")

--------------------------------------------------------------------
-- 5: is the handle still alive after the sweep?  a signal/clear tells us
--    whether the slot is still a usable object of some type
--------------------------------------------------------------------
print("--- 5: post-sweep ---")
print("  544(h) signal ret=" .. call(mk(544), uint64(h[1]), uint64(1)))
print("  546(h) clear  ret=" .. call(mk(546), uint64(h[1])))
local again = tag("557(name) after sweep", function() return mk(557)(uint64(name), uint64(0), uint64(0), uint64(0)) end)
print("  new handle=" .. again .. " (old " .. h[1] .. " reused? " .. tostring(again == h[1]) .. ")")
print("")

--------------------------------------------------------------------
-- 6: does the first argument select a type?  sweep 0..8
--------------------------------------------------------------------
print("--- 6: first-argument sweep, zeroed struct as the buffer ---")
for i = 0, 8 do
    local r = call(mk(557), uint64(i), uint64(st), uint64(0), uint64(0))
    print(string.format("  557(%d, struct) ret=%d", i, r))
end
print("[Z] alive=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== PROBE 557a COMPLETE ===")
