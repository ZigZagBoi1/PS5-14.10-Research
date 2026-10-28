-- CRASH_CLASS: LOW
-- PROBE 544n: MapDirectMemory — absolutely NO value access after call
--
-- After pcall of MapDM, DO NOT access mrv at all.
-- Only print literal strings and check if Lua is alive.
-- If Lua is alive, try reading virt_out with memory.read_dword only.
-- Also: test with *virt_out=target to see if it respects the hint.

print("=== 544n: MapDM NOREAD ===")
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

if not libkernel_base then print("FATAL"); return end
print("pid=" .. to_num(syscall.getpid()))

local map_fn = libkernel_base + uint64(0x15020)
local alloc_fn = libkernel_base + uint64(0x17EF0)

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
print("phys=" .. q(phys))

-- Prepare virt_out with hint at 0x880000000
local virt_out = memory.alloc(8)
wq(virt_out, uint64("0x880000000"))

-- Print addresses of everything important
print("virt_out_addr=" .. q(virt_out))
print("lk=" .. q(libkernel_base))

-- MapDM
print("MAP")
local ok_m = pcall(function()
    native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)

-- DO NOT access return value. Only print literals.
print("A")
print("B")
print("C")

-- Now carefully try to read virt_out with memory.read_dword
-- (which is a C function, not native handler)
print("D")
local lo = rd(to_num(virt_out))
print("E")
if lo then
    if lo < 0 then lo = lo + 0x100000000 end
    local hi_val = rd(to_num(virt_out) + 4)
    if hi_val then
        if hi_val < 0 then hi_val = hi_val + 0x100000000 end
        print(string.format("V=%08X%08X", hi_val, lo))

        -- If we got the mapped address, test R/W
        if hi_val ~= 0 or lo ~= 0 then
            local virt = uint64(string.format("0x%X%08X", hi_val, lo))
            print("T=" .. q(virt))
            wd(virt, 0xDEADBEEF)
            local rb = rd(to_num(virt))
            if rb then
                if rb < 0 then rb = rb + 0x100000000 end
                print(string.format("R=0x%X", rb))
            end
        end
    end
end

print("OK")
print("=== DONE ===")
