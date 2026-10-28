-- CRASH_CLASS: MODERATE
-- PROBE 88b: handle namespace, with the handle taken from the return value
--
-- 88a section A exposed a probe bug: sys 538 does not write the handle to the
-- out pointer (the buffer stayed 0) - it RETURNS it. Section A's eight create
-- cycles returned 0x4205 then 0x206..0x20C, one per create, while the pointer
-- stayed zero, and every later call used handle 0 and got -1.
--
-- Five subsystems were reported to share process+0xc48: event flags
-- (538-546), semaphores (549-556), generic objects (557), generic delete (558)
-- and aio (662-670). This probe uses the real handle values to ask whether a
-- handle is TYPED:
--
--   [1] event flag: create, signal, poll, wait, delete
--   [2] semaphore: create, post, trywait, delete
--   [3] cross-type calls: signal/delete a semaphore handle through the event
--       flag syscalls and the reverse; a 0 where the object does not exist in
--       that namespace means the handle carries no type
--   [4] slot reuse: does a semaphore take the slot an event flag just freed,
--       and does the old handle then reach the new object?

print("=== PROBE 88b: handle namespace with real handles ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function name(s)
    local b = memory.alloc(0x40); zero(b, 0x40)
    for i = 1, #s do pcall(function() memory.write_byte(b+i-1, string.byte(s,i)) end) end
    return b
end
local function call(f, ...)
    local ok, rv = pcall(f, ...)
    if not ok then return -999, "PCALL-FAIL" end
    return to_num(rv), tostring(rv)
end

print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))

--------------------------------------------------------------------
-- 1: event flag
--------------------------------------------------------------------
print("--- 1: event flag ---")
local ef = call(mk(538), uint64(name("ef88b")), uint64(0), uint64(0xAAAAAAAA), uint64(0))
print("  538 ef_create ret=" .. ef)
if ef <= 0 then print("[!] no event flag handle - stopping"); return end
print("  544 signal ret=" .. call(mk(544), uint64(ef), uint64(0x1234)))
local po = memory.alloc(8); wq(po, uint64(0))
print("  543 poll   ret=" .. call(mk(543), uint64(ef), uint64(0xFFFFFFFF), uint64(0), uint64(po)) ..
      " pattern=" .. string.format("%X", rq(po) or 0))
print("  546 clear  ret=" .. call(mk(546), uint64(ef)))
local wo = memory.alloc(8); wq(wo, uint64(0))
print("  545 wait   ret=" .. call(mk(545), uint64(ef), uint64(0xFFFFFFFF), uint64(0), uint64(wo)))
print("")

--------------------------------------------------------------------
-- 2: semaphore
--------------------------------------------------------------------
print("--- 2: semaphore ---")
local se = call(mk(549), uint64(name("se88b")), uint64(0), uint64(1), uint64(0x1000))
print("  549 sem_create ret=" .. se)
if se > 0 then
    print("  555 sem_post   ret=" .. call(mk(555), uint64(se), uint64(1)))
    print("  554 sem_trywait ret=" .. call(mk(554), uint64(se)))
    print("  552 sem_close   ret=" .. call(mk(552), uint64(se)))
end
print("")

--------------------------------------------------------------------
-- 3: cross-type calls
--------------------------------------------------------------------
print("--- 3: cross-type calls ---")
if se > 0 then
    print("  ef_signal(544) on semaphore handle " .. se .. " ret=" .. call(mk(544), uint64(se), uint64(0x1)))
    print("  ef_poll(543)   on semaphore handle " .. se .. " ret=" .. call(mk(543), uint64(se), uint64(0xFFFFFFFF), uint64(0), uint64(po)))
    print("  ef_delete(539) on semaphore handle " .. se .. " ret=" .. call(mk(539), uint64(se)))
end
if ef > 0 then
    print("  sem_post(555)  on event flag handle " .. ef .. " ret=" .. call(mk(555), uint64(ef), uint64(1)))
    print("  sem_trywait(554) on event flag handle " .. ef .. " ret=" .. call(mk(554), uint64(ef)))
    print("  sem_delete(550) on event flag handle " .. ef .. " ret=" .. call(mk(550), uint64(ef)))
end
print("")

--------------------------------------------------------------------
-- 4: slot reuse
--------------------------------------------------------------------
print("--- 4: slot reuse ---")
local a = call(mk(538), uint64(name("slotA")), uint64(0), uint64(0), uint64(0))
print("  create A -> " .. a)
print("  delete A -> " .. call(mk(539), uint64(a)))
local b = call(mk(538), uint64(name("slotB")), uint64(0), uint64(0), uint64(0))
print("  create B -> " .. b .. " (same as A? " .. tostring(a == b) .. ")")
local s2 = call(mk(549), uint64(name("slotS")), uint64(0), uint64(1), uint64(0x1000))
print("  create sem S -> " .. s2 .. " (equals A? " .. tostring(s2 == a) .. ")")
if s2 == a then
    print("  CROSS: the semaphore took the event flag's handle value")
    print("  ef_signal on old handle -> " .. call(mk(544), uint64(a), uint64(0x77)))
end
print("")

--------------------------------------------------------------------
-- 5: the generic object syscalls
--------------------------------------------------------------------
print("--- 5: 557/558 ---")
print("  557 create ret=" .. call(mk(557), uint64(name("gen")), uint64(0), uint64(0), uint64(0)))
print("  557 create ret=" .. call(mk(557), uint64(0), uint64(0), uint64(0), uint64(0)))
print("  558 delete(0x206,0) ret=" .. call(mk(558), uint64(0x206), uint64(0)))
print("  558 delete(0x206,1) ret=" .. call(mk(558), uint64(0x206), uint64(1)))
print("  558 delete(ef,0) ret=" .. call(mk(558), uint64(ef), uint64(0)))
print("[Z] alive=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== PROBE 88b COMPLETE ===")
