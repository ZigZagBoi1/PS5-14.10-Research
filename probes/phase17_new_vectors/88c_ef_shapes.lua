-- CRASH_CLASS: LOW
-- PROBE 88c: event flag argument shapes and stale handles
--
-- 88b proved the event flag family is reachable with a real handle (538
-- returns it) and that handles are typed and generation-checked. Two shapes
-- were still unknown: 543 (poll) returned -1, and 552 (sem_close) returned -1
-- on a handle 549 had just returned.
--
-- This probe sweeps the argument orders for 543 and 545 on an event flag whose
-- state we control, then asks whether a stale handle is refused after delete.
-- Nothing here races; a delete-while-waiting probe needs the multi-argument
-- child chain and is a separate step.

print("=== PROBE 88c: event flag shapes ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
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

print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))

local out = memory.alloc(8)
local ts1 = memory.alloc(16)   -- zero timespec = do not block
local ts2 = memory.alloc(16)   -- 0.5 s
zero(ts1, 16); zero(ts2, 16); wq(ts2+8, uint64(500000000))

local h = call(mk(538), uint64(nm("ef88c")), uint64(0), uint64(0), uint64(0))
print("[1] create ret=" .. h)
if h <= 0 then print("[!] no handle"); return end

print("[2] signal ret=" .. call(mk(544), uint64(h), uint64(0x1)))
print("")

print("--- poll shapes (expect 0 and the set pattern) ---")
local shapes = {
    {"(h, out, mask, mode)",      function() return mk(543)(uint64(h), uint64(out), uint64(0xFFFFFFFF), uint64(0)) end},
    {"(h, mask, out, mode)",      function() return mk(543)(uint64(h), uint64(0xFFFFFFFF), uint64(out), uint64(0)) end},
    {"(h, mode, mask, out)",      function() return mk(543)(uint64(h), uint64(0), uint64(0xFFFFFFFF), uint64(out)) end},
    {"(h, mask, mode, out)",      function() return mk(543)(uint64(h), uint64(0xFFFFFFFF), uint64(0), uint64(out)) end},
    {"(h, out, mode, mask)",      function() return mk(543)(uint64(h), uint64(out), uint64(0), uint64(0xFFFFFFFF)) end},
}
for i=1,#shapes do
    wq(out, uint64(0))
    local r = call(shapes[i][2])
    print(string.format("  %-24s ret=%d out=%X", shapes[i][1], r, rq(out) or 0))
end
print("")

print("--- wait shapes on a flagged object (expect immediate success) ---")
local waits = {
    {"(h, mask, ts, out)",  function() return mk(545)(uint64(h), uint64(0xFFFFFFFF), uint64(ts1), uint64(out)) end},
    {"(h, ts, mask, out)",  function() return mk(545)(uint64(h), uint64(ts1), uint64(0xFFFFFFFF), uint64(out)) end},
    {"(h, out, ts, mask)",  function() return mk(545)(uint64(h), uint64(out), uint64(ts1), uint64(0xFFFFFFFF)) end},
    {"(h, mask, out, ts)",  function() return mk(545)(uint64(h), uint64(0xFFFFFFFF), uint64(out), uint64(ts1)) end},
}
for i=1,#waits do
    wq(out, uint64(0))
    local r = call(waits[i][2])
    print(string.format("  %-24s ret=%d out=%X", waits[i][1], r, rq(out) or 0))
end
print("")

print("--- clear, then a 0.5 s wait: the wall clock says which shape blocks ---")
print("  clear ret=" .. call(mk(546), uint64(h)))
for i=1,4 do
    local r = call(waits[i][2])
    print(string.format("  %-24s ret=%d out=%X", waits[i][1], r, rq(out) or 0))
end
print("")

print("--- stale handle after delete ---")
print("  delete ret=" .. call(mk(539), uint64(h)))
print("  signal(stale) ret=" .. call(mk(544), uint64(h), uint64(0x1)))
print("  clear(stale)  ret=" .. call(mk(546), uint64(h)))
print("  delete(stale) ret=" .. call(mk(539), uint64(h)))
local h2 = call(mk(538), uint64(nm("ef88c2")), uint64(0), uint64(0), uint64(0))
print("  recreate ret=" .. h2 .. " (stale " .. h .. " reused? " .. tostring(h2 == h) .. ")")
print("  signal(old stale) ret=" .. call(mk(544), uint64(h), uint64(0x1)))
print("[Z] alive=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== PROBE 88c COMPLETE ===")
