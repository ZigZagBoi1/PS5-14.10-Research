-- CRASH_CLASS: HIGH
-- PROBE 1511a: destroy device vm_map entries in a loop -- does the object outlive the map?
--
-- Context: 1508a proved 548 op 3 + flags 0x10 deletes the vm_map_entry covering
-- the requested address and installs a fresh anonymous page (it landed exactly
-- on 0xF00000000 over SceGnmTrapCode, with no panic).  1509a grafted five
-- kernel-authored regions the same way and nothing wrote into the replacements.
--
-- What is still untested is the LIFETIME side: deleting an entry drops that
-- entry's reference to its vm_object.  A /dev/dmem0 mapping's object is owned by
-- the cdev and shared between descriptors (1396b: a store through the 0x1000
-- page of dmem0 was visible through dmem1's 0x1000 page, so two descriptors
-- reach one backing store).  If the cdev does NOT hold its own reference, then
-- deleting the entry frees the object while the descriptor still points at it,
-- and the next mmap of that descriptor is a use-after-free.  The fix for that
-- class is a reference count; the bug is that nobody tested it.
--
-- Design: keep the descriptor open the whole time, create/destroy mapping
-- entries in a loop, and re-verify with a read/write after every batch.  If the
-- object is freed and reused, either the process panics (the interesting
-- outcome) or the mapping stops round-tripping data (also interesting).
--
-- Chunk sync trap: this probe keeps NO cross-iteration state, only counters,
-- because a large table of addresses would be its own 8 MB.
--
-- prior art: results/phase36_realargs/1508a_sys548_map_fixed_20261109_224934.txt
--            results/phase36_realargs/1509a_graft_kernel_pages_20261109_225814.txt
--            results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt
--            results/phase36_realargs/1503a_mincore_aperture_20261109_221835.txt -- NOTE: 1503a's mincore 'oracle' reading is retracted,
-- see row 1503a-correction; a 0x40000 mincore writes 16 bytes, all resident

print("=== PROBE 1511a: DEVICE ENTRY DESTRUCTION LOOP ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local mk = {}
for _, n in ipairs({5, 20, 477, 547, 548}) do mk[n] = make_syscall(n) end

local function u32(v)
    local n = tonumber(v) or 0
    if n < 0 then n = n + 4294967296 end
    return n % 4294967296
end
local function sgn(v)
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(a1, a2, a3, a4, a5, a6) end)
    if ok then return r end
    return "EXC"
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return u32(to_num(v)) end
    return 0xDEADBEEF
end
local function wr(a, v)
    return pcall(function() memory.write_dword(a, uint64(v)) end)
end
local function pid() return tonumber(to_num(mk[20]())) end
print("[0] pid=" .. pid())

-- open /dev/dmem0 (string address needs a byte buffer, not a Lua string)
local pbuf = memory.alloc(0x40)
local name = "/dev/dmem0"
local i
for i = 1, #name do
    pcall(function() memory.write_byte(pbuf + i - 1, string.byte(name, i)) end)
end
pcall(function() memory.write_byte(pbuf + #name, 0) end)
local fd = sgn(call(mk[5], uint64(pbuf), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print("[0] open(/dev/dmem0, O_RDWR|O_NONBLOCK) fd=" .. fd)
if fd < 0 or fd > 4096 then
    print("  open failed -- INCOMPLETE")
    return
end

local ent = memory.alloc(0x40)
local done = memory.alloc(8)
local function map_fixed(va, len, prot)
    local k
    for k = 0, 0x3F, 4 do wr(ent + k, 0) end
    wr(ent + 0x00, va % 4294967296)
    wr(ent + 0x04, math.floor(va / 4294967296))
    wr(ent + 0x10, len % 4294967296)
    wr(ent + 0x14, math.floor(len / 4294967296))
    wr(ent + 0x18, prot)
    wr(ent + 0x1C, 3)
    wr(done, 0xEEEEEEEE)
    local rv = call(mk[548], uint64(0), uint64(0x10), uint64(ent), uint64(1), uint64(done), uint64(0))
    return sgn(rv), rd(done)
end

-- ------------------------------------------------------------------
-- [A] baseline: one mapping, one round trip
-- ------------------------------------------------------------------
print("")
print("--- [A] baseline ---")
local A = sgn(call(mk[477], uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0x4000)))
print(string.format("  mmap(dmem0 off 0x4000) A=0x%X", A))
if A < 0x4000 then print("  mmap failed -- INCOMPLETE") return end
wr(A, 0x11112222)
print(string.format("  A+0 = 0x%08X (want 11112222)", rd(A)))

-- a second descriptor on the same backing, to see whether the object is shared
local fd1 = sgn(call(mk[5], uint64(pbuf), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)))
print("  second open fd=" .. fd1)

-- ------------------------------------------------------------------
-- [B] destruction loop: replace the entry, then rebuild and re-verify
-- ------------------------------------------------------------------
print("")
print("--- [B] 200 rounds of mmap -> MAP_FIXED over it ---")
local bad = 0
for round = 1, 200 do
    local v = sgn(call(mk[477], uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0x4000)))
    if v < 0x4000 then
        print(string.format("  round %d: mmap refused (rv=0x%X)", round, v))
        bad = bad + 1
        break
    end
    if round == 1 then
        wr(v, 0x44445555)
        if rd(v) ~= 0x44445555 then
            print("  round 1: device page does not round-trip -- unexpected")
        end
    end
    local rv, proc = map_fixed(v, 0x4000, 3)
    if proc ~= 1 or rv ~= v then
        print(string.format("  round %d: MAP_FIXED rv=0x%X processed=%d (want 0x%X)", round, rv, proc, v))
        bad = bad + 1
    end
    if round % 50 == 0 then
        print(string.format("  round %d: pid=%d bad=%d", round, pid(), bad))
    end
end
print(string.format("  loop done, bad=%d, pid=%d", bad, pid()))

-- ------------------------------------------------------------------
-- [C] does the descriptor still work after 200 destroyed entries?
-- ------------------------------------------------------------------
print("")
print("--- [C] descriptor still usable? ---")
local B = sgn(call(mk[477], uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0x4000)))
print(string.format("  mmap after the loop B=0x%X", B))
if B > 0x4000 then
    wr(B, 0xAABBCCDD)
    local back = rd(B)
    print(string.format("  B+0 = 0x%08X (want AABBCCDD) %s", back,
        (back == 0xAABBCCDD) and "OK" or "*** the device page stopped round-tripping ***"))
end
local Z = sgn(call(mk[477], uint64(0), uint64(0x4000), uint64(1), uint64(1), uint64(fd), uint64(0)))
print(string.format("  mmap(dmem0 off 0) Z=0x%X", Z))
if Z > 0x4000 then
    print(string.format("  Z+0 = 0x%08X (register table expects C0012800)", rd(Z)))
end
if fd1 > 0 then
    local C = sgn(call(mk[477], uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd1), uint64(0x4000)))
    print(string.format("  mmap(fd1 off 0x4000) C=0x%X", C))
    if C > 0x4000 then
        wr(C, 0x13572468)
        print(string.format("  C+0 = 0x%08X (want 13572468)", rd(C)))
    end
end

print("")
print("final canary pid=" .. pid())
print("=== PROBE 1511a COMPLETE ===")
