-- CRASH_CLASS: LOW
-- PROBE 96f: what aio delete actually removes
--
-- 96e section B left a contradiction: 662 returned 0 with element status
-- 0x80020003 (ESRCH) and the 664 poll straight after it still reported state 3,
-- so the object survived its own delete. 898a saw a delete really free, but
-- only after cancel and poll had moved the element to state 4.
--
-- Section A: submit, poll, delete, poll, delete, poll - does the second delete
--            behave differently from the first?

print("=== PROBE 96f: aio delete semantics ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return -1 end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(f,...) local ok,rv=pcall(f,...) if not ok then return -999 end return to_num(rv) end
local function pid() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end
local function hx(v) return string.format("0x%X", v) end

local submit = mk(669)
local adele  = mk(662)
local apoll  = mk(664)
local cancel = mk(666)

local reqs = memory.alloc(0x28); zero(reqs, 0x28)
local ids  = memory.alloc(0x10); zero(ids, 0x10)
local st   = memory.alloc(0x10); zero(st, 0x10)
local er   = memory.alloc(0x10); zero(er, 0x10)

print("[0] pid=" .. tostring(pid()))

local r = call(submit, uint64(0x1001), uint64(reqs), uint64(1), uint64(3), uint64(ids))
print(string.format("[A] submit ret=%d id=%s", r, hx(rd(ids))))

local function poll(tag)
    zero(st, 0x10)
    local p = call(apoll, uint64(ids), uint64(1), uint64(st))
    print(string.format("    %-14s ret=%-3d st0=%s", tag, p, hx(rd(st))))
end
local function del(tag)
    zero(er, 0x10)
    local d = call(adele, uint64(ids), uint64(1), uint64(er))
    print(string.format("    %-14s ret=%-3d er0=%s", tag, d, hx(rd(er))))
end

poll("poll #1")
del("delete #1")
poll("poll #2")
del("delete #2")
poll("poll #3")
print(string.format("    cancel ret=%d er0=%s", call(cancel, uint64(ids), uint64(1), uint64(er)), hx(rd(er))))
poll("poll #4")
del("delete #3")
poll("poll #5")
del("delete #4")

print("[Z] alive=" .. tostring(pid()))
print("=== PROBE 96f COMPLETE ===")
