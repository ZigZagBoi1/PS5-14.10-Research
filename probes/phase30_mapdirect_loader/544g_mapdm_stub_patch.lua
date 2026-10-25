-- CRASH_CLASS: LOW
-- PROBE 544g: MapDirectMemory from main thread — careful diagnostics
--
-- 544f produced binary garbage. This probe:
-- 1. AllocDM from main (known working)
-- 2. Write sentinels in virt_out buffer
-- 3. Call MapDM from main thread via fcall_with_rax
--    (7th arg = return_addr = readable heap pointer, not NULL)
-- 4. Read virt_out regardless of Lua state health
-- 5. If MapDM returns error, report the code
--
-- The 7th arg (name) is a debug label. A readable heap pointer
-- should not crash — kernel just does copyin on it as a C string.
-- If MapDM fails, we need the error code to understand why.

print("=== PROBE 544g: MapDM MAIN THREAD DIAG ===")
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
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
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
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

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
if not ok_a or to_num(arv) ~= 0 then print("FATAL: AllocDM failed"); return end

-- [B] Prepare output buffer with clear sentinels
print("")
print("[B] Prepare virt_out")
local virt_out = memory.alloc(16)
wq(virt_out, uint64("0xDEADDEADDEADDEAD"))
wq(virt_out + uint64(8), uint64("0xBEEFBEEFBEEFBEEF"))
print("  virt_out=" .. q(virt_out))
print("  sentinel=" .. q(rq(virt_out)))

-- [C] Call MapDM
-- MapDirectMemory(void **virtAddrOut, size_t len, int prot, int flags,
--                 off_t physAddr, size_t alignment, const char *name)
-- via fcall_with_rax(fn, rax, rdi, rsi, rdx, rcx, r8, r9):
--   fn = map_fn, rax = 0
--   rdi = &virt_out (pointer to pointer)
--   rsi = 0x4000 (16KB, one page)
--   rdx = 3 (PROT_READ|PROT_WRITE)
--   rcx = 0 (flags)
--   r8  = phys (physical address from AllocDM)
--   r9  = 0x4000 (alignment = page)
--   7th = [RSP+8] at fn entry = return_addr in stub (readable heap ptr)
print("")
print("[C] MapDM")
print("  args: virt_out=" .. q(virt_out) .. " len=0x4000 prot=3 flags=0")
print("  phys=" .. q(phys) .. " align=0x4000 name=<stub residue>")

local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)

print("  pcall ok=" .. tostring(ok_m))
if ok_m then
    local rv_n = to_num(mrv)
    print("  rv raw=" .. q(mrv))
    -- Sony error codes: 0x800200XX
    if rv_n < 0 then rv_n = rv_n + 0x100000000 end
    print(string.format("  rv unsigned=0x%X", rv_n))
else
    print("  pcall error: " .. tostring(mrv))
end

-- [D] Read virt_out regardless
print("")
print("[D] Results")
local virt = rq(virt_out)
print("  virt_out[0]=" .. q(virt))
local virt8 = rq(virt_out + uint64(8))
print("  virt_out[8]=" .. q(virt8))

if ok_m then
    local rv_n = to_num(mrv)
    if rv_n == 0 then
        print("")
        print("  *** MapDM rv=0 ***")
        if virt and to_num(virt) ~= 0 then
            local vh, vl
            if type(virt) == "table" and virt.h then vh, vl = virt.h, virt.l
            else vl = to_num(virt); vh = 0 end
            if vh < 0 then vh = vh + 0x100000000 end
            if vl < 0 then vl = vl + 0x100000000 end
            local sentinel_intact = (vh == 0xDEADDEAD and vl == 0xDEADDEAD)
            if sentinel_intact then
                print("  virt_out sentinel unchanged — MapDM didn't write it")
            else
                print("  virt=" .. q(virt) .. " — MapDM WROTE a virtual address!")
                -- Test R/W on the mapped page
                local ok_w = pcall(function() memory.write_dword(virt, 0xDEADBEEF) end)
                print("  write ok=" .. tostring(ok_w))
                if ok_w then
                    local rb = rd(to_num(virt))
                    if rb then
                        if rb < 0 then rb = rb + 0x100000000 end
                        print(string.format("  read back: 0x%08X", rb))
                        if rb == 0xDEADBEEF then
                            print("  *** PHYSICAL MEMORY R/W CONFIRMED ***")
                        end
                    end
                end
            end
        end
    else
        if rv_n < 0 then rv_n = rv_n + 0x100000000 end
        print(string.format("  MapDM error: 0x%X", rv_n))
        -- Common Sony errors:
        -- 0x80020016 = EINVAL
        -- 0x80020023 = ENOMEM
        -- 0x80020009 = EBADF
        -- 0x80020003 = ESRCH
    end
end

-- [E] Canary
print("")
print("canary: ok=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== 544g DONE ===")
