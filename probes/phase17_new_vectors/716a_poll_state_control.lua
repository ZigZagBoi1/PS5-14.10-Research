-- CRASH_CLASS: LOW
-- PROBE 716a: is 0x10003 a normal state or a corruption artefact?
--
-- Context: after a delete, every surviving object's poll read 0x00010003 where
-- it had read 0x00000003 (probe 715a). Two readings fit:
--   (a) the table has a global state that flips once a delete has happened, or
--   (b) the objects share one block object S, which the hammer duplicated on the
--       freelist, so freeing one changes what the others see.
-- This is the control: the same sequence with no threads and no hammer at all.
-- If survivors flip here too, 0x10003 is ordinary and 715a's health line meant
-- nothing. If they do not, the hammer really did hand out a shared chunk.

print("=== PROBE 716a: poll state control (no race) ===")
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
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then pcall(function() for i=0,px-4,4 do memory.write_dword(v+i,0) end end) end
    return v
end

local data = mmap(page)
local polls = mmap(page)
local N = 6
local obj = {}
for i=1,N do
    local o = mmap(page)
    local ok, rv = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    local id = rd(o) or 0
    wd(polls, 0x77777777)
    pcall(function() mk(664)(uint64(o), uint64(1), uint64(polls)) end)
    obj[i] = {page=o, id=id, state=rd(polls) or 0}
end
local function dump(tag)
    local t = {}
    for i=1,N do
        if obj[i] then table.insert(t, string.format("%d=%08X", i, obj[i].state)) end
    end
    print(tag .. " " .. table.concat(t, " "))
end
dump("[A] after create ")

local s1 = mmap(page)
wd(s1, 0x77777777)
local okd, rvd = pcall(function() return mk(662)(uint64(obj[1].page), uint64(1), uint64(s1)) end)
print(string.format("[B] delete 1 rv=%s status=%08X", tostring(to_num(rvd)), rd(s1) or 0))
for i=2,N do
    wd(polls, 0x77777777)
    local okp, rvp = pcall(function() return mk(664)(uint64(obj[i].page), uint64(1), uint64(polls)) end)
    obj[i].state = rd(polls) or 0
end
dump("[B] survivors    ")

local o7 = mmap(page)
local o8 = mmap(page)
pcall(function() mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(o7)) end)
pcall(function() mk(664)(uint64(o7), uint64(1), uint64(polls)) end)
local st7 = rd(polls) or 0
pcall(function() mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(o8)) end)
pcall(function() mk(664)(uint64(o8), uint64(1), uint64(polls)) end)
local st8 = rd(polls) or 0
print(string.format("[C] fresh 7=%08X 8=%08X", st7, st8))

for i=2,N do
    local s = mmap(page)
    wd(s, 0x77777777)
    pcall(function() mk(662)(uint64(obj[i].page), uint64(1), uint64(s)) end)
end
print("[Z] done")
