-- CRASH_CLASS: HIGH
-- PROBE 949a: race mlfs lookup against unlink and rename
--
-- Context: 947a/947b showed the filesystem is correct when operations are
-- serialised, and 948a closed aio.  What has never been measured is mlfs under
-- concurrency, and the kernel image names `mlfs_roll_back_locking`, which is the
-- shape of a multi-step lock sequence that has to unwind when a later step fails
-- - the classic place for a use-after-free or a doubly freed vnode.
--
-- The harness can produce real concurrency: thr_create children run on the
-- kernel's own threads and reach their first syscall while the parent is still
-- executing Lua.  So:
--   child A : unlink(path)            (one call, from the context registers)
--   child B : rename(path, path2)     (one call)
--   parent  : 20000 x open(path) / ftruncate(fd,0) / close(fd)
-- The parent loop spans the children's execution window, so a lookup that does
-- not hold the name lock across the unlink will be exercised.
--
-- Success is boring: the loop finishes and the canary is intact.  A vnode that
-- is freed under a live lookup shows up either as a wrong open/close result or
-- as a dead process.

print("=== PROBE 949a: MLFS LOOKUP RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" then
        if v.tonumber then local n = v:tonumber() if n then return n end end
        if v.h then return v.h * 4294967296 + v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(a, n) pcall(function() for i = 0, n - 8, 8 do memory.write_qword(a + i, 0) end end) end
local function call(f, ...) local o, r = pcall(f, ...) if not o then return nil end return to_num(r) end

local pid = call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
print("[0] pid=" .. tostring(pid))
local fn = syscall.pipe.fn_addr

-- eboot base for the pop_rax gadget
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
call(function() return mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info + 0x10C) or 0) * 4294967296 + (rd(info + 0x108) or 0)
print(string.format("[0] eboot base=0x%X", ebase))

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
print("[0] pop_rax=" .. tostring(pop_rax))
if not pop_rax then print("[0] no gadget, abort") return end

local PAGE = 0x4000
local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

local path = "/av_contents/content_tmp/race949.bin"
local path2 = "/av_contents/content_tmp/race949b.bin"

-- seed the file
local sc_open, sc_write, sc_close = mk(5), mk(4), mk(6)
local fd0 = call(function() return sc_open(path, uint64(0x202), uint64(0x1FF)) end)
print("[1] seed open = " .. tostring(fd0))
if type(fd0) == "number" and fd0 >= 0 then
    local buf = mmap(PAGE)
    for i = 0, PAGE - 8, 8 do wq(buf + i, 0x94900000 + i) end
    print("[1] seed write = " .. tostring(call(function() return sc_write(uint64(fd0), uint64(buf), uint64(PAGE)) end)))
    call(function() return sc_close(uint64(fd0)) end)
end

local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100,
              RDI = 0x048, RSI = 0x050, RDX = 0x058, RCX = 0x060, R8 = 0x068, RAX = 0x078 }

local function build_ctx(ctx, start, rdi, rsi, rdx, rcx, r8, rax)
    wq(start, uint64(pop_rax)); wq(start + 8, uint64(431)); wq(start + 16, uint64(fn))
    zero(ctx, 0x500)
    wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
    wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
    wq(ctx + Ctx.RIP, uint64(fn)); wq(ctx + Ctx.RSP, uint64(start))
    wq(ctx + Ctx.RDI, uint64(rdi)); wq(ctx + Ctx.RSI, uint64(rsi))
    wq(ctx + Ctx.RDX, uint64(rdx)); wq(ctx + Ctx.RCX, uint64(rcx))
    wq(ctx + Ctx.R8, uint64(r8)); wq(ctx + Ctx.RAX, uint64(rax))
end

local blockA, blockB = mmap(PAGE * 2), mmap(PAGE * 2)
local ctxA = memory.alloc(0x500)
local ctxB = memory.alloc(0x500)
local tbA = memory.alloc(8)
local tbB = memory.alloc(8)

build_ctx(ctxA, blockA + PAGE * 2 - 0x200, 0, 0, 0, 0, 0, 10)  -- unlink == 10
build_ctx(ctxB, blockB + PAGE * 2 - 0x200, 0, 0, 0, 0, 0, 128) -- rename == 128

-- child A: unlink(path).  arg0 must be the path pointer, so marshal it first.
-- The loader passes Lua strings for syscall arguments, but a child thread reads
-- plain registers, so copy the path into a mapped page and pass its address.
local pA = mmap(PAGE)
pcall(function() memory.write_buffer(pA, path .. string.char(0)) end)
local pB = mmap(PAGE)
pcall(function() memory.write_buffer(pB, path2 .. string.char(0)) end)
build_ctx(ctxA, blockA + PAGE * 2 - 0x200, pA, 0, 0, 0, 0, 10)
build_ctx(ctxB, blockB + PAGE * 2 - 0x200, pA, pB, 0, 0, 0, 128)

print("[2] spawning unlink child and rename child")
for _, pair in ipairs({ { ctxA, tbA, "unlink" }, { ctxB, tbB, "rename" } }) do
    local ok, rv = pcall(function() return mk(430)(uint64(pair[1]), uint64(pair[2]), uint64(0)) end)
    print(string.format("    %-6s spawn ok=%s rv=%s tid=%s", pair[3], tostring(ok), tostring(ok and to_num(rv) or rv), tostring(rd(pair[2]))))
end

print("[3] parent loop: open / ftruncate / close")
local sc_trunc = mk(480)
local opened, failed, truncated, other = 0, 0, 0, 0
local ITERS = 20000
local t0 = os.clock()
for i = 1, ITERS do
    local fd = call(function() return sc_open(path, uint64(0x2), uint64(0)) end)
    if type(fd) == "number" and fd >= 0 then
        opened = opened + 1
        local r = call(function() return sc_trunc(uint64(fd), uint64(0)) end)
        if r == 0 then truncated = truncated + 1 else other = other + 1 end
        call(function() return sc_close(uint64(fd)) end)
    else
        failed = failed + 1
    end
end
print(string.format("    iters=%d opened=%d failed=%d truncated=%d other=%d (%.2fs)",
    ITERS, opened, failed, truncated, other, os.clock() - t0))

local after = call(function() return native.fcall_with_rax(fn, 20) end)
print("[4] canary pid=" .. tostring(after))
-- after the unlink child ran, the name should be gone: both final probes should fail
print("[4] open(path)  = " .. tostring(call(function() return sc_open(path, uint64(0x2), uint64(0)) end)))
print("[4] open(path2) = " .. tostring(call(function() return sc_open(path2, uint64(0x2), uint64(0)) end)))
print("")
print("=== PROBE 949a COMPLETE ===")
