-- CRASH_CLASS: MODERATE
-- PROBE 96e: does an aio call accept a 557 handle, and vice versa
--
-- 96d established the allocator: a LIFO free list over slots, with a shared
-- three-bit generation per slot (0x207 went 557 gen4 -> gen5 -> aio gen6, and
-- 0x208 went 557 gen1..gen4 -> aio gen5). So one slot really can be handed from
-- one family to the other with a generation that wraps back after eight reuses.
--
-- Two questions:
--  1. is the family checked before the handler touches the object at all?
--  2. if a stale aio id is made numerically equal to a live 557 handle, does the
--     aio handler still refuse it?
--
-- Section A: aio poll/wait/delete on a live 557 handle, then 558 to clean up.
-- Section B: 558 on a live aio id, then 662 to clean up.
-- Section C: put a 557 object on the slot the aio object just freed.
-- Section D: wrap that slot's generation back to the aio id and retry the aio
--            operations on the live 557 object.

print("=== PROBE 96e: cross-family handle use ===")

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
local function alive(tag) local p=pid() print("  alive="..tostring(p).." ("..tag..")") return p end

local create = mk(557)
local del    = mk(558)
local submit = mk(669)
local adele  = mk(662)
local apoll  = mk(664)
local await  = mk(663)

local name = memory.alloc(0x20); zero(name, 0x20)
for i=1,#"xf" do wb(name+i-1, string.byte("xf",i)) end
local reqs = memory.alloc(0x28); zero(reqs, 0x28)
local ids  = memory.alloc(0x10); zero(ids, 0x10)
local st   = memory.alloc(0x10); zero(st, 0x10)
local er   = memory.alloc(0x10); zero(er, 0x10)

print("[0] pid=" .. tostring(pid()))

print("")
print("--- A: aio operations on a live 557 handle ---")
local h = call(create, uint64(name), uint64(0), uint64(0), uint64(0))
print("  557 handle " .. sh(h))
if h > 0 then
    pcall(function() memory.write_dword(ids, h); memory.write_dword(ids+4, 0) end)
    zero(st, 0x10); zero(er, 0x10)
    print("  664 poll   ret=" .. call(apoll, uint64(ids), uint64(1), uint64(st)) .. " st0=" .. rd(st))
    print("  663 wait   ret=" .. call(await, uint64(ids), uint64(1), uint64(st), uint64(0)))
    print("  662 delete ret=" .. call(adele, uint64(ids), uint64(1), uint64(er)) .. " er0=" .. rd(er))
    print("  558 delete ret=" .. call(del, uint64(h)) .. " (0 means the 557 object was untouched)")
    alive("after A")
end

print("")
print("--- B: 558 on a live aio id ---")
zero(ids, 0x10)
local r = call(submit, uint64(0x1001), uint64(reqs), uint64(1), uint64(3), uint64(ids))
local aid = rd(ids)
print("  submit ret=" .. r .. " id " .. sh(aid))
if aid > 0 then
    print("  558 delete ret=" .. call(del, uint64(aid)))
    print("  662 delete ret=" .. call(adele, uint64(ids), uint64(1), uint64(er)) .. " er0=" .. rd(er))
    print("  664 poll   ret=" .. call(apoll, uint64(ids), uint64(1), uint64(st)) .. " st0=" .. rd(st))
    alive("after B")
end

print("")
print("--- C: 557 on the slot the aio object just freed ---")
if aid > 0 then
    local target = slot(aid)
    local match = nil
    for i = 1, 16 do
        local x = call(create, uint64(name), uint64(0), uint64(0), uint64(0))
        print(string.format("  %2d %s%s", i, sh(x), (x == aid) and "  <== equals the aio id" or ""))
        if x == aid then match = x break end
        if slot(x) == target then
            -- keep cycling on the target slot: delete and take it again
            call(del, uint64(x))
        else
            call(del, uint64(x))
        end
    end
    print("")
    print("--- D: aio operations on the wrapped 557 object ---")
    if match ~= nil then
        pcall(function() memory.write_dword(ids, match); memory.write_dword(ids+4, 0) end)
        zero(st, 0x10); zero(er, 0x10)
        print("  664 poll   ret=" .. call(apoll, uint64(ids), uint64(1), uint64(st)) .. " st0=" .. rd(st))
        print("  663 wait   ret=" .. call(await, uint64(ids), uint64(1), uint64(st), uint64(0)))
        print("  662 delete ret=" .. call(adele, uint64(ids), uint64(1), uint64(er)) .. " er0=" .. rd(er))
        print("  558 delete ret=" .. call(del, uint64(match)) .. " (0 = the 557 object was alive until here)")
        alive("after D")
    else
        print("  no generation match reached")
        alive("no match")
    end
end

print("")
print("[Z] alive=" .. tostring(pid()))
print("=== PROBE 96e COMPLETE ===")
