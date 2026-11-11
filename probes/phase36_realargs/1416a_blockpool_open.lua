-- CRASH_CLASS: MODERATE
-- PROBE 1416a: the blockpool family (653 open / 654 map / 655 unmap / 657 batch) with real args
--
-- prior art:
--   results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt
--     653 answers EINVAL(22) to a six-zero call and -1 to a mapped arg1, i.e. the syscall
--     dispatches for a game process; it was never called with a flag value it accepts.
--   docs/DEAD_ENDS.md - "sys 645/647/648/653/654/655/658/660/667 (653(0)=22 EINVAL,
--     everything else -1)"; 654/655/657 are listed only as "returns -1".
--   13.60 body of 653 at 0xffffffff8b367d10 (dump VA = 0x8a9c0000 + RVA):
--       mov r15d,[rsi]            ; uap[0] = flags
--       test r15d,0xffafffff      ; allowed bits are only 0x00500000
--       jne -> EINVAL
--       ... kmalloc 0x410b0, type 0x8102 ...
--       call 0x8b0ec7a0(td,&fp,&fd,flags|2,0)   ; installs a descriptor
--       mov [td+0x408], fd                       ; return 0
--   13.60 body of 654 at 0xffffffff8b369560: rbx = [proc+0x200]; gates
--       [rbx+0x20] > uap[0], [rbx+0x28] > uap[0], ([rbx+0x28]-uap[0]) >= uap[1],
--       (uap[0] & 0xffff) == 0, (uap[1] & 0xffff) == 0, uap[2] in {0,3,10},
--       uap[4] == 0, (uap[3] & 0xffffffcc) == 0. 655 has the same prologue.
--   13.60 body of 657 at 0xffffffff8b369f40: uap[0] = array pointer, uap[1] = signed count,
--       uap[2] = out pointer, uap[3] must be 0.
--
-- Reading: 654 and 655 refuse every shape we have tried because [proc+0x200] holds no entry
-- for the range, and only 653 can create one.  If 653 opens a pool for a game process, the
-- same connection should then answer 654 differently, and a fresh descriptor should appear.
--
-- Method: snapshot fstat over fds 0..48, call 653 with each flag value the body accepts,
-- snapshot again and print the diff, then call 654/655/657 with the shapes the 13.60 body
-- requires.  Nothing writes into a mapping we did not make ourselves.

print("=== PROBE 1416a: BLOCKPOOL OPEN ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sg(v) local n = N(v) if n >= 0x8000000000000000 then return n - 0x10000000000000000 end return n end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end

local pid = sg(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", pid))

local sc477 = mk(477)
local function mmap_pages(n)
    local va = N(sc477(uint64(0), uint64(0x1000 * n), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if va < 0x10000 or va > 0x8000000000 then return nil end
    return va
end

local ST = mmap_pages(2)
local OUT = mmap_pages(2)
local ARR = mmap_pages(2)
print(string.format("[0] ST=0x%X OUT=0x%X ARR=0x%X", ST or 0, OUT or 0, ARR or 0))
if not (ST and OUT and ARR) then print("[!] mmap failed: " .. es()) return end
for off = 0, 0x1FF0, 4 do pcall(function() memory.write_dword(ST + off, 0) end) end
for off = 0, 0x1FF0, 4 do pcall(function() memory.write_dword(OUT + off, 0) end) end
for off = 0, 0x1FF0, 4 do pcall(function() memory.write_dword(ARR + off, 0) end) end

local sc189 = mk(189)
local function fst(fd)
    local ok, rv = pcall(function() return sc189(uint64(fd), uint64(ST), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return "EXC" end
    local n = sg(rv)
    if n == 0 then return 0 end
    return n
end

local function snapshot(tag)
    local s = {}
    for fd = 0, 48 do
        local r = fst(fd)
        s[fd] = r
        if r == 0 then io.write(string.format(" fd%d=OK", fd)) end
    end
    print(string.format("[%s] fstat sweep done", tag))
    return s
end

local sc653 = mk(653)
local sc654 = mk(654)
local sc655 = mk(655)
local sc657 = mk(657)

local function call6(sc, a, b, c, d, e)
    local ok, rv = pcall(function() return sc(uint64(a or 0), uint64(b or 0), uint64(c or 0), uint64(d or 0), uint64(e or 0), uint64(0)) end)
    if not ok then return "EXC" end
    return sg(rv)
end

print("[1] descriptor snapshot before")
local before = snapshot("A")

print("[2] 653 blockpool_open, every flag value the body accepts")
local FLAGS = { 0, 0x100000, 0x400000, 0x500000, 0x500001, 0xFFFFFFFF }
local opened = {}
for _, f in ipairs(FLAGS) do
    local rv = call6(sc653, f)
    print(string.format("  653(0x%08X) -> rv=%s errno=%s", f, tostring(rv), es()))
    if rv == 0 then opened[#opened + 1] = f end
end

print("[3] descriptor snapshot after")
local after = snapshot("B")
for fd = 0, 48 do
    if before[fd] ~= after[fd] then
        print(string.format("  fd %d: %s -> %s", fd, tostring(before[fd]), tostring(after[fd])))
    end
end

print("[4] 654 blockpool_map with the shapes the 13.60 body requires")
local SHAPES = {
    { 0, 0x10000, 0, 0, 0 },
    { 0, 0x10000, 3, 0, 0 },
    { 0, 0x10000, 10, 0, 0 },
    { 0x10000, 0x10000, 0, 0, 0 },
    { 0, 0x100000, 0, 0, 0 },
    { 0, 0x1000000, 0, 0, 0 },
    { 0, 0, 0, 0, 0 },
}
for _, s in ipairs(SHAPES) do
    local rv = call6(sc654, s[1], s[2], s[3], s[4], s[5])
    print(string.format("  654(0x%X,0x%X,%d,%d,%d) -> rv=%s errno=%s out0=%s",
        s[1], s[2], s[3], s[4], s[5], tostring(rv), es(), hex4(rd(OUT))))
end

print("[5] 655 unmap and 657 batch")
print(string.format("  655(0,0x10000) -> rv=%s errno=%s", tostring(call6(sc655, 0, 0x10000)), es()))
print(string.format("  655(0x10000,0x10000) -> rv=%s errno=%s", tostring(call6(sc655, 0x10000, 0x10000)), es()))
print(string.format("  657(ARR,0,OUT,0) -> rv=%s errno=%s", tostring(call6(sc657, ARR, 0, OUT, 0)), es()))
print(string.format("  657(ARR,1,OUT,0) -> rv=%s errno=%s", tostring(call6(sc657, ARR, 1, OUT, 0)), es()))

print("[6] 653 again after the map attempts (state check)")
print(string.format("  653(0x100000) -> rv=%s errno=%s", tostring(call6(sc653, 0x100000)), es()))

print("=== PROBE 1416a COMPLETE ===")
