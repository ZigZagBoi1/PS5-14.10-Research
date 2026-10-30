-- CRASH_CLASS: LOW
-- PROBE 939e: does PROT_EXEC survive into the VM entry? (sys 547 oracle)
--
-- Context: 939c showed mprotect refuses 5/7 on anonymous AND file mappings
-- while mmap with prot=5 and prot=7 succeeds.  Two explanations remain:
--   (a) mmap drops the X bit when it builds the entry, so nothing ever has it;
--   (b) the entry keeps X and something lower (pmap) refuses to execute.
--
-- sys 547 reports the protection word of the region containing an address.
-- Measured values so far: heap prot=3 -> 0x03 low bits, GPU prot=3 -> 0x33.
-- If a prot=5 file mapping reports 0x05, the entry carries X and (b) holds;
-- if it reports 0x03, mmap stripped it and (a) holds.
--
-- A: anon prot=3 (baseline 0x03)
-- B: file mapping, prot=3 / 5 / 7 -> protection word each
-- C: the same regions' start/end, to prove the queries hit our mappings
--
-- No thread is spawned.

print("=== PROBE 939e: ENTRY-LEVEL PROTECTION ORACLE ===")
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
local function call(f, ...)
    local ok, rv = pcall(f, ...)
    if not ok then return "PCALL-FAIL" end
    return to_num(rv)
end

local sc_mmap, sc_open, sc_write, sc547 = mk(477), mk(5), mk(4), mk(547)
local PAGE = 0x4000
local out = memory.alloc(0x40)

local function mmap(px, prot, flags, fd)
    return call(function() return sc_mmap(uint64(0), uint64(px), uint64(prot), uint64(flags), uint64(fd), uint64(0)) end)
end

local function region(tag, addr)
    if type(addr) ~= "number" or addr <= 0 then
        print(string.format("[%s] no mapping", tag))
        return
    end
    for i = 0, 0xF do wd(out + i * 4, 0xDEAD0000 + i) end
    local r = call(function() return sc547(uint64(addr), uint64(out)) end)
    if r == 0 then
        print(string.format("[%s] 0x%X ret=%s start=%s end=%s prot=0x%X flag=0x%X", tag, addr, tostring(r),
            tostring(rq(out)), tostring(rq(out + 8)), rd(out + 0x10) or 0, rd(out + 0x14) or 0))
    else
        print(string.format("[%s] 0x%X ret=%s (query failed)", tag, addr, tostring(r)))
    end
end

print("[0] pid=" .. tostring(call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)))

local anon = mmap(PAGE, 3, 0x1002, 0xFFFFFFFF)
region("A anon=3", anon)

local fd = call(function() return sc_open("/av_contents/content_tmp/xcode.bin", uint64(0x202), uint64(0x1FF)) end)
print("[B] open xcode.bin = " .. tostring(fd))
if type(fd) == "number" and fd >= 0 then
    local buf = mmap(PAGE, 3, 0x1002, 0xFFFFFFFF)
    if type(buf) == "number" and buf > 0 then
        for i = 0, 0x1F do pcall(function() memory.write_byte(buf + i, 0xC3) end) end
        print("[B] write = " .. tostring(call(function() return sc_write(uint64(fd), uint64(buf), uint64(0x20)) end)))
    end
    for _, prot in ipairs({3, 5, 7}) do
        local m = mmap(PAGE, prot, 0x2, fd)
        print(string.format("[B] file mmap prot=%d -> %s first byte=%s", prot, tostring(m), tostring(rd(m))))
        region(string.format("B file=%d", prot), m)
    end
    -- and one MAP_SHARED variant, in case the private path is the one that strips X
    local ms = mmap(PAGE, 5, 0x1, fd)
    print("[B] file mmap prot=5 MAP_SHARED -> " .. tostring(ms))
    region("B file=5 sh", ms)
end

print("")
print("=== PROBE 939e COMPLETE ===")
