-- CRASH_CLASS: LOW
-- PROBE 545f: MapDirectMemory — test MAP_FIXED flag (0x10) with hint address
--
-- The hint *virt_out=0x880000000 alone doesn't prevent kernel choosing
-- a random address. MAP_FIXED (0x10) should force it.
-- Also test: flags = MAP_NO_COALESCE | 0x10 = 0x400010
--
-- Run THREE tests:
-- A) flags=0x400010 with hint, NO pre-mmap (address free)
-- B) If A fails: flags=0x10 with hint
-- C) If both fail: pre-mmap then munmap then MapDM (free slot)

print("=== 545f: MAPFIXED ===")
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

local alloc_fn = libkernel_base + uint64(0x17EF0)
local map_fn = libkernel_base + uint64(0x15020)
local target = uint64("0x880000000")
local target_int = to_num(target)

-- AllocDM
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
if not ok_a or to_num(arv) ~= 0 then print("ALLOC FAIL"); return end
local phys = rq(phys_out)
print("P=" .. q(phys))

-- Test A: MapDM with flags = MAP_NO_COALESCE | 0x10, hint = 0x880000000
local virt_out_a = memory.alloc(8)
wq(virt_out_a, target)

print("[A] MAP 0x400010")
io.flush()
local ok_ma, rv_a = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out_a), uint64(0x4000), uint64(0x33),
        uint64(0x400010), phys, uint64(0x4000))
end)
print("[A] ok=" .. tostring(ok_ma))
io.flush()

if ok_ma then
    local n = to_num(rv_a)
    if n < 0 then n = n + 0x100000000 end
    print(string.format("[A] rv=0x%X", n))
    io.flush()

    if n == 0 then
        -- MapDM succeeded! Test the target directly
        print("[A] WRITE")
        io.flush()
        local ok_w = wd(target, 0xDEADBEEF)
        print("[A] wd=" .. tostring(ok_w))
        io.flush()

        if ok_w then
            print("[A] READ")
            io.flush()
            local v = rd(target_int)
            if v then
                if v < 0 then v = v + 0x100000000 end
                print(string.format("[A] v=0x%08X", v))
                if v == 0xDEADBEEF then
                    print("*** [A] DIRECT MEMORY R/W AT 0x880000000 ***")

                    -- Dump 32 bytes
                    print("DUMP:")
                    for off = 0, 28, 4 do
                        local dw = rd(target_int + off)
                        if dw then
                            if dw < 0 then dw = dw + 0x100000000 end
                            io.write(string.format("%08X ", dw))
                        end
                    end
                    print("")
                end
            else
                print("[A] rd=FAULT")
            end
        end

        print("pid=" .. to_num(syscall.getpid()))
        print("DONE")
        return
    end
end

-- Test B: same but flags = 0x10 only
-- Need fresh phys (or can reuse if A failed without mapping)
print("[B] alloc2")
local phys_out2 = memory.alloc(8)
wq(phys_out2, uint64(0))
local ok_a2, arv2 = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out2))
end)
if not ok_a2 or to_num(arv2) ~= 0 then print("[B] ALLOC FAIL"); return end
local phys2 = rq(phys_out2)
print("[B] P=" .. q(phys2))

local virt_out_b = memory.alloc(8)
wq(virt_out_b, target)

print("[B] MAP 0x10")
io.flush()
local ok_mb, rv_b = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out_b), uint64(0x4000), uint64(0x33),
        uint64(0x10), phys2, uint64(0x4000))
end)
print("[B] ok=" .. tostring(ok_mb))
io.flush()

if ok_mb then
    local n = to_num(rv_b)
    if n < 0 then n = n + 0x100000000 end
    print(string.format("[B] rv=0x%X", n))
    io.flush()

    if n == 0 then
        print("[B] WRITE")
        io.flush()
        local ok_w = wd(target, 0xBEEFCAFE)
        print("[B] wd=" .. tostring(ok_w))
        io.flush()
        if ok_w then
            local v = rd(target_int)
            if v then
                if v < 0 then v = v + 0x100000000 end
                print(string.format("[B] v=0x%08X", v))
                if v == 0xBEEFCAFE then
                    print("*** [B] DIRECT MEMORY R/W AT 0x880000000 ***")
                end
            end
        end
    end
end

print("pid=" .. to_num(syscall.getpid()))
print("DONE")
