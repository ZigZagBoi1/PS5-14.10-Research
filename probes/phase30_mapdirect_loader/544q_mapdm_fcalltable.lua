-- CRASH_CLASS: LOW
-- PROBE 544q: MapDirectMemory via fcall() table (not native.fcall_with_rax)
--
-- The Apollo loader calls MapDM with 6 args via fcall():
--   sceKernelMapDirectMemory = fcall(dlsym(LIBKERNEL_HANDLE, "sceKernelMapDirectMemory"))
--   local ret = sceKernelMapDirectMemory(out, size, prot, flag, phys_addr, size):tonumber()
--
-- fcall() is a callable Lua table. When native_invoke exists, it delegates
-- to native.fcall_with_rax. BUT we can bypass that by directly using
-- fcall.create_initial_chain() path with execute_through_coroutine().
--
-- Actually, since native_invoke exists in our loader, fcall.__call always
-- uses native.fcall_with_rax. There's no way to force the coroutine path.
--
-- DIFFERENT APPROACH: The crash dump 0x1337 is from the loader's signal handler.
-- It's not necessarily fatal. Let's call MapDM and then communicate the result
-- back to the PC via a DIFFERENT CHANNEL (not stdout which gets corrupted).
--
-- Channel: write the result to a socketpair or network socket BEFORE any
-- stdout print. Or: write a marker to a known address and have the PC
-- make a SECOND connection to read it.
--
-- SIMPLEST: call MapDM, then write the virt_out value to the TCP socket
-- directly using write() syscall, bypassing stdout.
--
-- BUT: the simplest simplest: just use fcall() which IS native.fcall_with_rax.
-- Let's try and see.

print("=== 544q: MapDM FCALL ===")
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
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
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

if not libkernel_base then print("FATAL"); return end
print("pid=" .. to_num(syscall.getpid()))

local map_fn = libkernel_base + uint64(0x15020)
local alloc_fn = libkernel_base + uint64(0x17EF0)

-- Create fcall objects (these are callable tables)
local MapDM = fcall(map_fn)
local AllocDM = fcall(alloc_fn)

print("MapDM=" .. tostring(MapDM))
print("AllocDM=" .. tostring(AllocDM))

-- AllocDM
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return AllocDM(uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
if not ok_a then print("ALLOC pcall FAIL"); return end
local arv_n = to_num(arv)
if arv_n ~= 0 then
    if arv_n < 0 then arv_n = arv_n + 0x100000000 end
    print(string.format("ALLOC err=0x%X", arv_n)); return
end
local phys = rq(phys_out)
print("phys=" .. q(phys))

-- MapDM via fcall table
local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))

print("MAP...")
local ok_m, mrv = pcall(function()
    return MapDM(uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)

print("BACK")
print("ok=" .. tostring(ok_m))

if ok_m then
    local rv_n = to_num(mrv)
    print("rv=" .. rv_n)

    if rv_n == 0 then
        print("MAP OK!")
        -- Read virt_out carefully - use pcall
        print("reading...")
        local ok_r, lo = pcall(function() return memory.read_dword(virt_out) end)
        print("rd_ok=" .. tostring(ok_r))
        if ok_r then
            lo = to_num(lo)
            if lo < 0 then lo = lo + 0x100000000 end
            local ok_r2, hi = pcall(function() return memory.read_dword(virt_out + uint64(4)) end)
            if ok_r2 then
                hi = to_num(hi)
                if hi < 0 then hi = hi + 0x100000000 end
                print(string.format("virt=%08X%08X", hi, lo))
            end
        end
    else
        if rv_n < 0 then rv_n = rv_n + 0x100000000 end
        print(string.format("err=0x%X", rv_n))
    end
end

print("C=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== DONE ===")
