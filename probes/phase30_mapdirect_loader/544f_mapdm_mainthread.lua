-- CRASH_CLASS: LOW
-- PROBE 544f: MapDirectMemory from MAIN THREAD via fcall_with_rax
--
-- Key insight: the 7th arg (name) is a debug label string pointer.
-- When we call via fcall_with_rax, [RSP+8] at function entry will be
-- whatever was in the fcall_stub after the return_addr slot — probably
-- a pointer to the main chain (readable heap). MapDirectMemory may
-- just read a few bytes as a "name" string and not crash.
--
-- If it crashes because name is garbage: we'll try writing NULL to
-- the stub area first.
--
-- AllocDM works from main thread. MapDM should too if TLS is the issue.

print("=== PROBE 544f: MapDM MAIN THREAD ===")
io.stdout:setvbuf("no")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end

if not libkernel_base then print("FATAL: no libkernel_base"); return end
print("libkernel=" .. q(libkernel_base))
print("pid=" .. to_num(syscall.getpid()))

local map_fn = libkernel_base + uint64(0x15020)
local alloc_fn = libkernel_base + uint64(0x17EF0)

-- [A] AllocDM
print("")
print("[A] AllocDM")
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  rv=" .. (ok_a and to_num(arv) or "FAIL") .. " phys=" .. q(phys))

if not ok_a or to_num(arv) ~= 0 then
    print("  FATAL: AllocDM failed")
    return
end

-- [B] MapDM via fcall_with_rax (6 register args, 7th = whatever is on stack)
print("")
print("[B] MapDM via fcall_with_rax")
local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))

-- MapDirectMemory(virtAddrOut, len, prot, flags, physAddr, alignment, name)
-- via fcall_with_rax(fn, rax, rdi, rsi, rdx, rcx, r8, r9):
--   fn = map_fn
--   rax = 0 (unused)
--   rdi = &virt_out
--   rsi = 0x4000
--   rdx = 3 (PROT_READ|PROT_WRITE)
--   rcx = 0 (flags)
--   r8 = phys
--   r9 = 0x4000 (alignment)
--   7th arg (name) = [RSP+8] at entry = uncontrolled (stub residue)

local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)

local virt = rq(virt_out)
print("  ok=" .. tostring(ok_m))
print("  rv=" .. (ok_m and q(mrv) or "PCALL_FAIL"))
print("  virt=" .. q(virt))

if ok_m and to_num(mrv) == 0 and virt and to_num(virt) ~= 0 then
    print("  *** MapDM SUCCEEDED ***")
    pcall(function() memory.write_dword(virt, 0xDEADBEEF) end)
    local rb = rd(to_num(virt))
    if rb then
        if rb < 0 then rb = rb + 0x100000000 end
        print(string.format("  R/W: wrote 0xDEADBEEF read 0x%08X", rb))
        if rb == 0xDEADBEEF then
            print("  *** R/W VERIFIED ON PHYSICAL MEMORY ***")
        end
    end
elseif ok_m then
    -- Got an error code, not a crash
    local n = to_num(mrv); if n < 0 then n = n + 0x100000000 end
    print(string.format("  MapDM error: 0x%X", n))

    -- [C] Try with flags that might help
    print("")
    print("[C] MapDM with different flags")

    -- flags=0x10 (MAP_FIXED-like? probably not, but try)
    wq(virt_out, uint64(0))
    local ok2, rv2 = pcall(function()
        return native.fcall_with_rax(map_fn, 0,
            uint64(virt_out), uint64(0x4000), uint64(3),
            uint64(0x10), phys, uint64(0x4000))
    end)
    print("  flags=0x10: rv=" .. (ok2 and q(rv2) or "FAIL"))

    -- flags=1
    wq(virt_out, uint64(0))
    local ok3, rv3 = pcall(function()
        return native.fcall_with_rax(map_fn, 0,
            uint64(virt_out), uint64(0x4000), uint64(3),
            uint64(1), phys, uint64(0x4000))
    end)
    print("  flags=0x1: rv=" .. (ok3 and q(rv3) or "FAIL"))

    -- prot=1 (read only)
    wq(virt_out, uint64(0))
    local ok4, rv4 = pcall(function()
        return native.fcall_with_rax(map_fn, 0,
            uint64(virt_out), uint64(0x4000), uint64(1),
            uint64(0), phys, uint64(0x4000))
    end)
    print("  prot=1: rv=" .. (ok4 and q(rv4) or "FAIL"))
else
    print("  MapDM crashed the native handler")
end

-- Canary
print("")
print("canary: ok=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== 544f DONE ===")
