-- CRASH_CLASS: LOW
-- PROBE 972a: validate the store gadgets before any child uses them
--
-- A two-byte match can land mid-instruction; 928a died exactly that way. This
-- probe only reads: it locates each candidate, prints the eight bytes around it and
-- the module-relative offset, so a race probe can refuse a bad gadget instead of
-- jumping into the middle of an instruction.

print("=== PROBE 972a: GADGET VALIDATION ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end

local info=memory.alloc(0x200) for i=0,0x1FC,4 do wd(info+i,0) end wd(info,0x160)
pcall(function() mk(593)(uint64(0),uint64(info)) end)
local base=rd(info+0x10C)*4294967296+rd(info+0x108)
local size=rd(info+0x110)
print(string.format("[0] base=0x%X size=0x%X fn=0x%X", base, size, to_num(syscall.pipe.fn_addr)))

local function hex(a,n)
    local o,s=pcall(function() return memory.read_buffer(a,n) end)
    if not o or type(s)~="string" then return "<unreadable>" end
    local out={}
    for i=1,#s do out[#out+1]=string.format("%02X",string.byte(s,i)) end
    return table.concat(out," ")
end
local function find_all(pat, limit)
    local hits={}
    local off=0
    while off<size and #hits<(limit or 3) do
        local want=size-off if want>0x1000 then want=0x1000 end
        local o,s=pcall(function() return memory.read_buffer(base+off,want) end)
        if not o or type(s)~="string" then break end
        local i=1
        while #hits<(limit or 3) do
            local j=string.find(s,pat,i,true)
            if not j then break end
            hits[#hits+1]=base+off+j-1
            i=j+1
        end
        off=off+want
    end
    return hits
end
local cands={
    {"pop_rax 58 C3",       string.char(0x58,0xC3)},
    {"mov [rdi],rax 488907C3", string.char(0x48,0x89,0x07,0xC3)},
    {"mov [rsi],rax 488906C3", string.char(0x48,0x89,0x06,0xC3)},
    {"ret C3",              string.char(0xC3)},
}
for _,c in ipairs(cands) do
    local h=find_all(c[2], 3)
    print(string.format("[%s] hits=%d", c[1], #h))
    for k,a in ipairs(h) do
        print(string.format("   +0x%X  0x%X  bytes: %s", a-base, a, hex(a-8,16)))
    end
end
print("[Z] alive pid=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
