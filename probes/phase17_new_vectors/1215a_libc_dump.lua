-- CRASH_CLASS: LOW
-- PROBE 1215a: libc module info, then dump libc .text so its import call sites can be
--              analysed offline. Goal: prove which libc import slot is a >=4-argument
--              libkernel syscall stub, so syscall argument 4 (r10) becomes reachable.
print("=== PROBE 1215a: libc module info + text dump ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(a) local hi=math.floor(a/4294967296) return string.format("0x%08X%08X",hi,a-hi*4294967296) end
local function rq(a) local ok,v=pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local lc = N(libc_base)
print(string.format("[0] libc_base=%s", hexn(lc)))
local mi = memory.alloc(0x300)
local gmi = fcall(libc_addrofs.sceKernelGetModuleInfoFromAddr)
print(string.format("[0] gmi(libc)=0x%X", gmi(libc_base, 1, mi):tonumber()))
for off = 0x100, 0x1A0, 0x8 do local v = rq(mi + off) if v then print(string.format("      mi+0x%03X = %s", off, hexn(v))) end end
local textbase, textsize = rq(mi + 0x160), rq(mi + 0x168)
print(string.format("[0] text=%s rec=%s", hexn(textbase or 0), hexn(textsize or 0)))
local size = (textsize or 0) % 0x100000000
if size <= 0 or size > 0x400000 then
    print("[!] unexpected text size, dumping 0x100000")
    size = 0x100000
end
-- also dump the libc data segment: the import table itself, so slot offsets are known offline
local dbase, drec = rq(mi + 0x170), rq(mi + 0x178)
print(string.format("[0] data=%s rec=%s", hexn(dbase or 0), hexn(drec or 0)))
local CH = 0x1000
local donet = 0
while donet < size do
    local want = math.min(CH, size - donet)
    local ok, buf = pcall(function() return memory.read_buffer(textbase + donet, want) end)
    if not ok then print(string.format("[!] text read failed at +0x%X", donet)) break end
    print(string.format("[T] off=0x%X len=0x%X %s", donet, want, (buf:gsub(".", function(c) return string.format("%02X", string.byte(c)) end))))
    donet = donet + want
end
local dsize = (drec or 0) % 0x100000
if dbase and dbase > 0x10000 and dsize > 0 and dsize <= 0x100000 then
    local ddone = 0
    while ddone < dsize do
        local want = math.min(CH, dsize - ddone)
        local ok, buf = pcall(function() return memory.read_buffer(dbase + ddone, want) end)
        if not ok then print(string.format("[!] data read failed at +0x%X", ddone)) break end
        print(string.format("[E] off=0x%X len=0x%X %s", ddone, want, (buf:gsub(".", function(c) return string.format("%02X", string.byte(c)) end))))
        ddone = ddone + want
    end
end
print("=== DONE ===")
