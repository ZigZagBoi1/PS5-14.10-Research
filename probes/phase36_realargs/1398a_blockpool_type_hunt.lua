-- CRASH_CLASS: LOW -- every blockpool_move call passes the same address in the source and
-- destination slots, and the handler takes its "nothing to do" exit (0x9ab30e-0x9ab320: return 0
-- when len == 0 or uap[1] == uap[0]) BEFORE it touches any block, so a call that passes the
-- vm_object type gate still performs no operation. Nothing here reads GPU memory.
-- PROBE 1398a: find the mappings whose vm_object type is 0xb, the one gate the whole blockpool
-- family sits behind.
--
-- 1397a showed that no mapping a game process can create with plain mmap satisfies the gate - not
-- the anonymous GPU heap, not /dev/dmem0, not /dev/zero, not POSIX shm, not the heap - and that a
-- blockpool descriptor cannot be mmap'd at all (rdev 0xB000, eight mmap shapes all EINVAL, read
-- EBADF, ioctl ENOTTY). So the type-0xb object must already exist in this process, created by
-- something other than a syscall we have tried. The game process has GPU memory mapped by
-- SceGnmDriver, and sys 674 prints every region of this process's own map with its name, so the
-- question becomes measurable: walk the map and ask each region whether it is type 0xb.
--
-- The oracle is blockpool_move (673) with uap[1] == uap[0]. Its body
-- (results/kernel_handlers/asm/sys_673.asm:13154) runs the following in order:
--   vmspace = proc+0x200; if addr < vmspace[0x20] or addr >= vmspace[0x28]  -> EINVAL
--   (addr | uap[1]) & 0xFFFF != 0                                          -> EINVAL
--   uap[2] & 0xFFFF != 0, uap[3] != 0, uap[2] > end-addr, uap[1] checks    -> EINVAL
--   lock; vm_map_lookup_entry(vmspace, addr, &entry)
--   entry[0x60] & 2, entry[0x50] == NULL                                   -> EINVAL
--   entry->object->type (byte at object+0x9d) != 0xb                       -> EINVAL
--   if (uap[2] == 0 || uap[1] == addr) return 0            <-- the safe exit
--   otherwise the 64 KiB block move runs
-- So a 0 answer is proof that the lookup found a type-0xb object at that address, and no block is
-- ever moved. An EINVAL answer cannot distinguish "no object" from "wrong type", but a 0 is decisive.
--
-- -- prior art:
--   results/phase36_realargs/1396a_blockpool_open_20261109_142118.txt (descriptor mint works)
--   results/phase36_realargs/1397a_blockpool_map_probe_20261109_142241.txt (every plain mapping fails the gate)
--   results/kernel_handlers/asm/sys_673.asm:13154 (the body and the safe exit)
--   results/phase14_final_push/55e_vm_cred_survey.lua:67 (sys 674 call shape and record layout)
--   docs/DEAD_ENDS.md:85 (673 refused for the GPU backing object)

print("=== PROBE 1398a: TYPE 0xB MAPPING HUNT ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = N(v) % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function rq(a) local ok,v = pcall(function() return N(memory.read_qword(a)) end) if ok then return v % 4294967296 end return nil end
local function strz(a, n)
    local out = {}
    for i = 0, n - 1 do
        local c = nil
        local ok, v = pcall(function() return memory.read_byte(a + i) end)
        if ok then c = N(v) % 256 end
        if not c or c == 0 then break end
        if c >= 32 and c < 127 then out[#out + 1] = string.char(c) else out[#out + 1] = "." end
    end
    return table.concat(out)
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end
print("[0] SIG_IGN installed")

-- ---------------------------------------------------------------- A: the map
print("")
print("[A] sys 674 virtual_query_all")
local STRIDE, MAXR = 72, 512
local buf = memory.alloc(STRIDE * MAXR)
for i = 0, STRIDE * MAXR - 1, 8 do pcall(function() memory.write_qword(buf + i, uint64(0)) end) end
local countp = memory.alloc(16)
pcall(function() memory.write_qword(countp, uint64(0)) end)
local rv674 = N(mk(674)(uint64(N(buf)), uint64(STRIDE), uint64(MAXR), uint64(N(countp)), uint64(0x40000000), uint64(0)))
local n = rd(countp)
print(string.format("   674 -> %d  count=%s  %s", rv674, n and tostring(n) or "?", es()))

local REGIONS = {}
if n and n > 0 and n <= MAXR then
    for i = 0, n - 1 do
        local r = buf + i * STRIDE
        local st = rq(r)
        local en = rq(r + 8)
        local pr = rd(r + 0x18)
        local nm = strz(r + 0x20, 24)
        if st and en then
            REGIONS[#REGIONS + 1] = {st, en, pr or 0, nm}
        end
    end
end
print(string.format("   regions collected: %d", #REGIONS))
for i, r in ipairs(REGIONS) do
    print(string.format("   %3d  0x%08X..0x%08X  p=%s  %s", i, r[1], r[2],
        hex(r[3]), r[4] ~= "" and r[4] or "-"))
end

-- ---------------------------------------------------------------- B: the gate
print("")
print("[B] blockpool_move(addr, addr, 0x10000, 0) on the 64 KiB-aligned interior of every region")
local HITS, TESTED = {}, 0
for i, r in ipairs(REGIONS) do
    local st, en = r[1], r[2]
    if en > st and (en - st) >= 0x10000 then
        local a = st
        local rem = a % 0x10000
        if rem ~= 0 then a = a + (0x10000 - rem) end
        if a + 0x10000 <= en then
            TESTED = TESTED + 1
            local rv = N(mk(673)(uint64(a), uint64(a), uint64(0x10000), uint64(0), uint64(0), uint64(0)))
            if rv == 0 then
                HITS[#HITS + 1] = {a, r[3], r[4], i}
                print(string.format("   >>> 0x%08X..0x%08X  p=%s  %s   TYPE 0xB MATCH", a, a + 0x10000,
                    hex(r[3]), r[4] ~= "" and r[4] or "-"))
            elseif rv ~= -1 then
                print(string.format("   ?   0x%08X p=%s %s -> %d %s", a, hex(r[3]), r[4], rv, es()))
            end
        end
    end
end
print(string.format("   tested=%d hits=%d", TESTED, #HITS))

-- ---------------------------------------------------------------- C: the fallback, a coarse scan
if #HITS == 0 then
    print("")
    print("[C] no region answered 0; scanning the high device band at 2 MiB steps")
    for _, base in ipairs({0x800000000, 0x900000000, 0xA00000000, 0xB00000000,
                           0xC00000000, 0xD00000000, 0xE00000000, 0xF00000000,
                           0x1000000000, 0x2000000000, 0x3000000000}) do
        local a = base
        for k = 0, 31 do
            local addr = a + k * 0x200000
            local rv = N(mk(673)(uint64(addr), uint64(addr), uint64(0x10000), uint64(0), uint64(0), uint64(0)))
            if rv == 0 then
                HITS[#HITS + 1] = {addr, 0, "scan", 0}
                print(string.format("   >>> 0x%X TYPE 0xB MATCH", addr))
            end
        end
    end
    print(string.format("   [C] scan hits=%d", #HITS))
end

print("")
print("=== PROBE 1398a COMPLETE ===")
