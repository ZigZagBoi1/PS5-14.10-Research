-- CRASH_CLASS: HIGH
-- PROBE 606a: the aiocb layout (fildes@0, opcode@4, buf@8, nbytes@0x10, offset@0x18)
print("=== PROBE 606a: AIOCB LAYOUT ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end

local sc_sp,sc_create,sc_poll,sc_del,sc_write=mk(135),mk(669),mk(664),mk(662),mk(4)
local sv=memory.alloc(8) wq(N(sv),uint64(0))
pcall(function() sc_sp(uint64(1),uint64(1),uint64(0),U(N(sv))) end)
local fda,fdb=rd(N(sv)),rd(N(sv)+4)
print(string.format("[A] fd_a=%d fd_b=%d",fda,fdb))

local buf=memory.alloc(0x4000)
local data=memory.alloc(0x100)
local out=memory.alloc(0x40)
local cell=memory.alloc(16)
local pollo=memory.alloc(0x40)

local function make(op, len)
    for i=0,0xFC,4 do wd(N(data)+i,0) end
    wd(N(data)+0,fda)            -- aio_fildes
    wd(N(data)+4,op)             -- aio_lio_opcode
    wq(N(data)+8,U(N(buf)))      -- aio_buf
    wq(N(data)+0x10,U(len))      -- aio_nbytes
    wq(N(data)+0x18,uint64(0))   -- aio_offset
    wq(N(out),uint64(0))
    local ok,rv=pcall(function() return sc_create(uint64(1),U(N(data)),uint64(1),uint64(1),U(N(out))) end)
    if not ok or N(rv)~=0 then return nil, N(rv) end
    return rd(N(out)), 0
end
local function poll(id)
    wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
    pcall(function() sc_poll(U(N(cell)),uint64(1),U(N(pollo))) end)
    return rd(N(pollo))
end

local id=make(0,0x100)
print(string.format("[B] read op=0 empty fd=%d id=%s poll=%s", fda, id and string.format("%08X",id) or "nil", id and string.format("%08X",poll(id)) or "-"))
if id then
    wd(N(cell),id) wd(N(pollo),0xCCCCCCCC)
    local ok,rv=pcall(function() return sc_del(U(N(cell)),uint64(1),U(N(pollo))) end)
    print(string.format("[C] delete pending ret=%s status=%08X",N(rv),rd(N(pollo))))
end

local id2=make(1,0x100)
print(string.format("[D] write op=1 id=%s poll=%s", id2 and string.format("%08X",id2) or "nil", id2 and string.format("%08X",poll(id2)) or "-"))

local id3=make(2,0x100)
print(string.format("[E] nop op=2 id=%s poll=%s", id3 and string.format("%08X",id3) or "nil", id3 and string.format("%08X",poll(id3)) or "-"))

-- write data, then a read that should complete
local msg=memory.alloc(0x200)
for i=0,0x1FC,4 do wd(N(msg)+i,0x41424344) end
pcall(function() sc_write(U(fdb),U(N(msg)),uint64(0x200),uint64(0),uint64(0),uint64(0)) end)
local id4=make(0,0x100)
print(string.format("[F] read with data id=%s poll=%s buf0=%08X", id4 and string.format("%08X",id4) or "nil", id4 and string.format("%08X",poll(id4)) or "-", rd(N(buf))))

print("[Z] alive")
