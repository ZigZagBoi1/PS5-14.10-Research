-- CRASH_CLASS: LOW
-- PROBE 544t: MapDirectMemory — use EXACT Apollo loader flags
--
-- DISCOVERY: Apollo uses prot=0x33 and flags=0x400000, NOT prot=3 flags=0
-- - PROT_READ=0x1 | PROT_WRITE=0x2 | GPU_READ=0x10 | GPU_WRITE=0x20 = 0x33
-- - MAP_NO_COALESCE = 0x400000 (prevents kernel from merging with adjacent mappings!)
--
-- Our probes used prot=3, flags=0 → kernel may coalesce new mapping into
-- existing heap/loader regions → crash.
--
-- This probe uses the exact same values as the Apollo loader.
-- Also: AllocateMainDirectMemory uses different args than AllocateDirectMemory?
-- Check: Apollo calls sceKernelAllocateMainDirectMemory, NOT sceKernelAllocateDirectMemory

print("=== 544t: MapDM APOLLO FLAGS ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end

if not libkernel_base then print("FATAL"); return end
print("pid=" .. to_num(syscall.getpid()))
print("lk=" .. q(libkernel_base))

-- Sony constants (from Apollo globals.lua)
local PROT_READ  = 0x01
local PROT_WRITE = 0x02
local GPU_READ   = 0x10
local GPU_WRITE  = 0x20
local MAP_NO_COALESCE = 0x400000

local prot = bit32.bor(PROT_READ, PROT_WRITE, GPU_READ, GPU_WRITE)  -- 0x33
print(string.format("prot=0x%X", prot))

local alloc_fn = libkernel_base + uint64(0x17EF0)
local map_fn = libkernel_base + uint64(0x15020)

-- AllocateDirectMemory (0x17EF0)
-- Apollo calls sceKernelAllocateMainDirectMemory — check if same fn
local out = memory.alloc(8)
wq(out, uint64(0))

print("ALLOC...")
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0),                   -- search start
        uint64("0x150000000"),       -- search end (GetDirectMemorySize)
        uint64(0x4000),              -- size (16KB = 1 page)
        uint64(0x4000),              -- alignment (page aligned)
        uint64(0),                   -- mem type? (Apollo might use different)
        uint64(out))                 -- output phys addr
end)
if not ok_a then print("ALLOC pcall FAIL: " .. tostring(arv)); return end
local arv_n = to_num(arv)
if arv_n ~= 0 then
    if arv_n < 0 then arv_n = arv_n + 0x100000000 end
    print(string.format("ALLOC err=0x%X", arv_n))
    return
end

local phys = rq(out)
print("phys=" .. q(phys))

-- MapDirectMemory with Apollo flags
wq(out, uint64(0))  -- let kernel choose virt addr

print("MAP...")
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(out),                 -- arg1: &virt_addr (in/out)
        uint64(0x4000),              -- arg2: size
        uint64(prot),                -- arg3: prot = 0x33 (R|W|GPU_R|GPU_W)
        uint64(MAP_NO_COALESCE),     -- arg4: flags = 0x400000
        phys,                        -- arg5: phys_addr
        uint64(0x4000))              -- arg6: alignment
end)

-- Post-MapDM: print results carefully
print("A")
print("ok=" .. tostring(ok_m))

if not ok_m then
    print("FAIL:" .. tostring(mrv))
    return
end

print("B")
local rv_n = to_num(mrv)
print("rv=" .. rv_n)

if rv_n ~= 0 then
    if rv_n < 0 then rv_n = rv_n + 0x100000000 end
    print(string.format("err=0x%X", rv_n))
    return
end

-- MapDM returned 0 — now read the virtual address
print("C:reading_virt")
local virt = rq(out)
if virt then
    print("virt=" .. q(virt))

    -- Test R/W on the mapped page
    print("D:write")
    local ok_w = wd(virt, 0xDEADBEEF)
    print("wd=" .. tostring(ok_w))

    print("E:read")
    local v = rd(to_num(virt))
    if v then
        if v < 0 then v = v + 0x100000000 end
        print(string.format("rd=0x%08X", v))
        if v == 0xDEADBEEF then
            print("*** DIRECT MEMORY R/W WORKS ***")
        end
    else
        print("rd=FAULT")
    end
else
    print("virt=NIL")
end

-- Canary
print("F:canary")
print("pid=" .. to_num(syscall.getpid()))

print("=== DONE ===")
