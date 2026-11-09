-- CRASH_CLASS: LOW
-- PROBE 544d: AllocateDirectMemory diagnostics
--
-- 544b/544c got ENOMEM (0x80020023) from AllocDM. Need to understand why.
-- Test: different sizes, memoryTypes, search ranges.
-- Also: check GetDirectMemorySize and current allocation state.

print("=== PROBE 544d: AllocDM DIAGNOSTICS ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end

if not libkernel_base then print("FATAL: no libkernel_base"); return end
print("libkernel=" .. q(libkernel_base))
print("pid=" .. to_num(syscall.getpid()))

local alloc_fn = libkernel_base + uint64(0x17EF0) -- AllocateDirectMemory
local getdm_fn = libkernel_base + uint64(0x17810) -- GetDirectMemorySize
print("AllocDM=" .. q(alloc_fn))
print("GetDMSize=" .. q(getdm_fn))

-- [A] GetDirectMemorySize
print("")
print("[A] GetDirectMemorySize")
local ok_g, dm_size = pcall(function()
    return native.fcall_with_rax(getdm_fn, 0)
end)
print("  rv=" .. (ok_g and q(dm_size) or "FAIL"))

-- [B] Try AllocDM via native.fcall_with_rax (6 args, known working from DEM9N101)
print("")
print("[B] AllocDM via fcall_with_rax")

local function try_alloc(label, start, end_, size, align, memtype)
    local phys_out = memory.alloc(8)
    wq(phys_out, uint64(0))
    local ok, rv = pcall(function()
        return native.fcall_with_rax(alloc_fn, 0,
            uint64(start), uint64(end_), uint64(size),
            uint64(align), uint64(memtype), uint64(phys_out))
    end)
    local phys = rq(phys_out)
    local rv_n = ok and to_num(rv) or -1
    if rv_n < 0 then rv_n = rv_n + 0x100000000 end
    print(string.format("  %s: rv=0x%X phys=%s", label, rv_n, phys and q(phys) or "nil"))
    return rv_n, phys
end

-- Standard: full range, 1 page, type 0
try_alloc("full_range_t0", 0, "0x150000000", 0x4000, 0x4000, 0)
-- Type 1 (write-combine)
try_alloc("full_range_t1", 0, "0x150000000", 0x4000, 0x4000, 1)
-- Type 2
try_alloc("full_range_t2", 0, "0x150000000", 0x4000, 0x4000, 2)
-- Type 3
try_alloc("full_range_t3", 0, "0x150000000", 0x4000, 0x4000, 3)
-- Type 10
try_alloc("full_range_t10", 0, "0x150000000", 0x4000, 0x4000, 10)

-- Smaller size (4KB)
try_alloc("4kb", 0, "0x150000000", 0x1000, 0x1000, 0)
-- Minimum (256 bytes)
try_alloc("256b", 0, "0x150000000", 0x100, 0x100, 0)

-- Different search ranges
try_alloc("range_1G", "0x100000000", "0x140000000", 0x4000, 0x4000, 0)
try_alloc("range_first256M", 0, "0x10000000", 0x4000, 0x4000, 0)
try_alloc("range_high", "0x140000000", "0x150000000", 0x4000, 0x4000, 0)

-- [C] Try via loader thread (same as 544b)
print("")
print("[C] AllocDM via thread:new")
local phys_out2 = memory.alloc(8)
wq(phys_out2, uint64(0))

local chain = ropchain({ fcall_stub_padding_size = 0x50000 })
chain:push_fcall_with_ret(alloc_fn,
    uint64(0), uint64("0x150000000"), uint64(0x4000),
    uint64(0x4000), uint64(0), uint64(phys_out2)
)
local ok_t, thr = pcall(function() return thread:new(chain) end)
if ok_t then
    pcall(function() thr:run(true) end)
    pcall(function() thr:join() end)
    local rv = rq(chain:get_last_retval_addr())
    local phys = rq(phys_out2)
    print("  rv=" .. q(rv) .. " phys=" .. q(phys))
end

-- [D] If all fail, try ReleaseDirectMemory to free some space
-- ReleaseDirectMemory: libkernel+0x17DB0 (estimated offset)
-- Signature: ReleaseDirectMemory(physAddr, len)
-- We don't have a valid phys addr to release, so skip for now.

print("")
print("canary: ok=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== 544d DONE ===")
