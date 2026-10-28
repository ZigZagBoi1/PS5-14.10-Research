-- CRASH_CLASS: LOW
-- PROBE 96d: how the shared handle allocator picks a slot
--
-- 96c assumed the allocator hands out the lowest free slot; it does not - after
-- the aio object was deleted from slot 0x205, the next 557 create went to 0x207.
-- The ABA test needs to force a chosen slot, so the rule has to be measured.
--
-- Section A: five 557 creates, no deletes - the slot order.
-- Section B: delete them, five more - does it reuse or move on?
-- Section C: one aio create, print its slot; delete; then 557 - where does it
--            land relative to the aio slot?
-- Section D: 557 create/delete pair followed by an aio create - does the aio
--            take the slot the 557 object just freed?

print("=== PROBE 96d: allocator order ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return -1 end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(f,...) local ok,rv=pcall(f,...) if not ok then return -999 end return to_num(rv) end
local function pid() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end
local function slot(h) return h % 0x2000 end
local function gen(h) return math.floor(h / 0x2000) end
local function sh(h) return string.format("0x%X slot=0x%X gen=%d", h, slot(h), gen(h)) end

local create = mk(557)
local del    = mk(558)
local submit = mk(669)
local adele  = mk(662)

local name = memory.alloc(0x20); zero(name, 0x20)
for i=1,#"ord" do wb(name+i-1, string.byte("ord",i)) end
local reqs = memory.alloc(0x28); zero(reqs, 0x28)
local ids  = memory.alloc(0x10); zero(ids, 0x10)
local er   = memory.alloc(0x10); zero(er, 0x10)

print("[0] pid=" .. tostring(pid()))

print("")
print("--- A: five consecutive creates ---")
local held = {}
for i = 1, 5 do
    local h = call(create, uint64(name), uint64(0), uint64(0), uint64(0))
    held[i] = h
    print("  " .. i .. " " .. sh(h))
end

print("")
print("--- B: delete them, five more ---")
for i = 1, 5 do call(del, uint64(held[i])) end
for i = 1, 5 do
    local h = call(create, uint64(name), uint64(0), uint64(0), uint64(0))
    held[i] = h
    print("  " .. i .. " " .. sh(h))
end
for i = 1, 5 do call(del, uint64(held[i])) end

print("")
print("--- C: aio create then 557 create ---")
zero(ids, 0x10)
local r = call(submit, uint64(0x1001), uint64(reqs), uint64(1), uint64(3), uint64(ids))
local A = rd(ids)
print("  aio submit ret=" .. r .. " id " .. sh(A))
print("  aio delete ret=" .. call(adele, uint64(ids), uint64(1), uint64(er)))
local h = call(create, uint64(name), uint64(0), uint64(0), uint64(0))
print("  557 after the aio delete: " .. sh(h))
call(del, uint64(h))

print("")
print("--- D: 557 create/delete then aio create ---")
h = call(create, uint64(name), uint64(0), uint64(0), uint64(0))
print("  557 first: " .. sh(h))
call(del, uint64(h))
local h2 = call(create, uint64(name), uint64(0), uint64(0), uint64(0))
print("  557 again: " .. sh(h2))
call(del, uint64(h2))
zero(ids, 0x10)
r = call(submit, uint64(0x1001), uint64(reqs), uint64(1), uint64(3), uint64(ids))
local B = rd(ids)
print("  aio submit ret=" .. r .. " id " .. sh(B))
call(adele, uint64(ids), uint64(1), uint64(er))

print("")
print("[Z] alive=" .. tostring(pid()))
print("=== PROBE 96d COMPLETE ===")
