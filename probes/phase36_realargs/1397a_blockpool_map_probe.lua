-- CRASH_CLASS: MODERATE -- every 654/655/673 call returns EINVAL unless the mapping it names is
-- backed by a vm_object of type 0xb, and only a call that passes that gate mutates anything; the
-- mmap sweep is read-free. The last section touches a device mapping's aligned interior, which the
-- range checks in all three handlers accept before the type gate.
-- PROBE 1397a: what can a blockpool descriptor do, and which of our mappings is type 0xb?
--
-- 1396a established that blockpool_open (653) still mints real descriptors on 14.10 (22, 23, 527
-- for flags 0, 0x100000, 0x400000). This probe asks two questions about the rest of the family.
--
-- Question 1 - the descriptor. 653 installs f_ops 0x255fec8 with f_data = the 0x410b0-byte pool
-- object, so read/write/ioctl/mmap all reach that table. 1396a's single mmap shape
-- (0x40000, PROT_READ|WRITE, MAP_SHARED, offset 0) returned EINVAL; the sweep here varies prot,
-- flags, length and offset, and records st_mode/st_dev/rdev from fstat so the descriptor's driver
-- class is named rather than guessed.
--
-- Question 2 - the type gate. blockpool_map (654), blockpool_unmap (655) and blockpool_move (673)
-- take a user VA, look it up in the process's own vm_map (proc+0x200 -> vmspace), and require
-- `entry->object->type == 0xb` (byte at object+0x9d). Nothing else. docs/DEAD_ENDS.md:85 records
-- 673 refusing the GPU anonymous mapping, but an anonymous MAP_PRIVATE page has no backing object
-- at all, so that test could never have reached the type comparison. The candidates below are the
-- mappings that DO have an object: a MAP_SHARED file mapping (/app0/eboot.bin), MAP_SHARED device
-- mappings (/dev/dmem0, /dev/gc, /dev/zero), a POSIX shm mapping (482), and, for contrast, the
-- anonymous GPU heap. Every call is 64 KiB aligned and length 0x10000, which is what all three
-- handlers require before they touch the map, so a return of 0 means the type matched and the block
-- operation actually ran.
--
-- -- prior art:
--   results/phase36_realargs/1396a_blockpool_open_20261109_142118.txt (descriptor mint works)
--   results/kernel_handlers/asm/sys_654.asm:11469 (blockpool_map, the 0xb gate)
--   results/kernel_handlers/asm/sys_655.asm (blockpool_unmap, same gate)
--   results/kernel_handlers/asm/sys_657.asm:4114 (blockpool_batch, opcode jump table 1..5)
--   results/kernel_handlers/asm/sys_673.asm:13154 (blockpool_move, same gate)
--   docs/DEAD_ENDS.md:85 (673 refused for the GPU backing object)

print("=== PROBE 1397a: BLOCKPOOL DESCRIPTOR AND THE TYPE 0xB GATE ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = N(v) % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function rq(a) local ok,v = pcall(function() return N(memory.read_qword(a)) end) if ok then return v % 4294967296 end return nil end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end
print("[0] SIG_IGN installed")

local O_RDWR = 2
local O_NONBLOCK = 0x4000
local MAP_SHARED, MAP_PRIVATE, MAP_ANON = 1, 2, 0x1000

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(b + #s, 0) end)
    return N(b)
end
local function open_node(path)
    return N(mk(5)(uint64(str_addr(path)), uint64(O_RDWR + O_NONBLOCK), uint64(0), uint64(0), uint64(0), uint64(0)))
end
local function mm(addr, len, prot, flags, fd, off)
    local ok, rv = pcall(function()
        return mk(477)(uint64(addr), uint64(len), uint64(prot), uint64(flags), uint64(fd), uint64(off))
    end)
    if not ok then return -99999 end
    return N(rv)
end
local function up64(v) if v < 0 then return v end local a = v % 0x10000 if a ~= 0 then return v + (0x10000 - a) end return v end

-- ---------------------------------------------------------------- A
print("")
print("[A] fstat on the descriptors 653 minted")
local FDS = {}
for _, f in ipairs({0, 0x100000, 0x400000}) do
    local rv = N(mk(653)(uint64(f), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
    local note = ""
    if rv >= 3 and rv < 4096 then FDS[#FDS + 1] = rv else note = " (not a descriptor)" end
    print(string.format("   653(0x%X) -> %d%s", f, rv, note))
end
for _, fd in ipairs(FDS) do
    local st = memory.alloc(0x200)
    for i = 0, 0x100, 8 do pcall(function() memory.write_qword(st + i, uint64(0)) end) end
    local frv = N(mk(189)(uint64(fd), uint64(st), uint64(0), uint64(0), uint64(0), uint64(0)))
    print(string.format("   fd=%d fstat -> %d  mode=%s dev=%s rdev=%s size=%s/%s", fd, frv,
        hex(rd(st + 4)), hex(rd(st)), hex(rd(st + 8)),
        rd(st + 0x50) and hex(rd(st + 0x50)) or "?", rd(st + 0x54) and hex(rd(st + 0x54)) or "?"))
end

-- ---------------------------------------------------------------- B
print("")
print("[B] mmap shapes on the first descriptor")
if #FDS == 0 then
    print("   no descriptor, skipped")
else
    local fd = FDS[1]
    local hits = 0
    for _, prot in ipairs({3, 1, 2, 0x33}) do
        for _, flags in ipairs({MAP_SHARED, MAP_PRIVATE}) do
            for _, len in ipairs({0x10000, 0x40000}) do
                for _, off in ipairs({0, 0x10000}) do
                    local a = mm(0, len, prot, flags, fd, off)
                    local tag = ""
                    if a > 0 and a ~= -1 then
                        tag = "  <- MAPPED"
                        hits = hits + 1
                        local v = rd(a)
                        tag = tag .. " +0=" .. (v and hex(v) or "?")
                    end
                    print(string.format("   mmap(len=0x%X, prot=0x%X, fl=0x%X, off=0x%X) -> %d %s%s",
                        len, prot, flags, off, a, es(), tag))
                end
            end
        end
    end
    print(string.format("   [B] mapped shapes: %d", hits))
    print("[B] read/timeout probes on the descriptor")
    local buf = memory.alloc(0x1000)
    for i = 0, 0xFFC, 8 do pcall(function() memory.write_qword(buf + i, uint64(0x4142434445464748)) end) end
    local rrv = N(mk(3)(uint64(fd), uint64(buf), uint64(0x40), uint64(0), uint64(0), uint64(0)))
    print(string.format("   read(fd=%d, 0x40) -> %d %s  buf+0=%s", fd, rrv, es(), rd(buf) and hex(rd(buf)) or "?"))
    for _, cmd in ipairs({0x4004667F, 0x8004667E, 0x4004667A}) do
        local irv = N(mk(54)(uint64(fd), uint64(cmd), uint64(buf), uint64(0), uint64(0), uint64(0)))
        print(string.format("   ioctl(fd=%d, 0x%X) -> %d %s buf+0=%s", fd, cmd, irv, es(), rd(buf) and hex(rd(buf)) or "?"))
    end
end

-- ---------------------------------------------------------------- C
print("")
print("[C] type-0xb survey: blockpool_move(addr, 0, 0x10000, 0) on every mapping that has an object")
local CANDS = {}

local gpu = mm(0, 0x200000, 0x33, MAP_ANON + MAP_PRIVATE, -1, 0)
if gpu > 0 then CANDS[#CANDS + 1] = {"anon gpu heap", gpu} end

for _, path in ipairs({"/dev/dmem0", "/dev/gc", "/dev/zero"}) do
    local fd = open_node(path)
    if fd >= 3 then
        local a = mm(0, 0x40000, 3, MAP_SHARED, fd, 0)
        if a > 0 and a ~= -1 then CANDS[#CANDS + 1] = {path, a} end
        pcall(function() return N(mk(6)(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    end
end

local ffd = open_node("/app0/eboot.bin")
if ffd < 3 then ffd = open_node("/app0/eboot.bin") end
if ffd >= 3 then
    for _, fl in ipairs({MAP_SHARED, MAP_PRIVATE}) do
        local a = mm(0, 0x40000, 1, fl, ffd, 0)
        if a > 0 and a ~= -1 then
            CANDS[#CANDS + 1] = {string.format("eboot.bin fl=0x%X", fl), a}
        end
    end
    pcall(function() return N(mk(6)(uint64(ffd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
end

local shmfd = N(mk(482)(uint64(str_addr("/probe1397a")), uint64(0x202), uint64(0600), uint64(0), uint64(0), uint64(0)))
print(string.format("   482 shm_open -> %d %s", shmfd, es()))
if shmfd >= 3 then
    pcall(function() return N(mk(480)(uint64(shmfd), uint64(0x40000), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    local a = mm(0, 0x40000, 3, MAP_SHARED, shmfd, 0)
    if a > 0 and a ~= -1 then CANDS[#CANDS + 1] = {"posix shm", a} end
end

local heap = N(memory.alloc(0x20000))
CANDS[#CANDS + 1] = {"heap alloc", heap}

print(string.format("   candidates: %d", #CANDS))
for _, c in ipairs(CANDS) do
    local name, base = c[1], up64(c[2])
    print(string.format("   -- %s base=0x%X aligned=0x%X", name, c[2], base))
    local rv = N(mk(673)(uint64(base), uint64(0), uint64(0x10000), uint64(0), uint64(0), uint64(0)))
    local e = es()
    print(string.format("      673(0x%X,0,0x10000,0) -> %d %s%s", base, rv, e, rv == 0 and "   <<< TYPE 0xB MATCH" or ""))
end

-- ---------------------------------------------------------------- D
print("")
print("[D] 657 blockpool_batch on a record array aimed at the anonymous heap")
local rec = memory.alloc(0x200)
for i = 0, 0x1F8, 8 do pcall(function() memory.write_qword(rec + i, uint64(0)) end) end
pcall(function() memory.write_dword(rec, 1) end)
pcall(function() memory.write_dword(rec + 8, up64(heap)) end)
for _, cnt in ipairs({1, 0}) do
    local rv = N(mk(657)(uint64(N(rec)), uint64(cnt), uint64(0), uint64(0), uint64(0), uint64(0)))
    print(string.format("   657(rec, count=%d, 0, 0) -> %d %s", cnt, rv, es()))
end

for _, fd in ipairs(FDS) do
    pcall(function() return N(mk(6)(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
end

print("")
print("=== PROBE 1397a COMPLETE ===")
