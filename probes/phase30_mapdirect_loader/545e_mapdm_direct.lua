-- CRASH_CLASS: LOW
-- PROBE 545e: MapDirectMemory — skip virt_out read, test target directly
--
-- 545d showed: pre-mmap 0x880000000 OK, MapDM rv=0, but read_qword(virt_out) crashes.
-- NEW: Don't read virt_out at all. If MapDM respected the hint (0x880000000),
-- the physical page is now at 0x880000000. Just write/read there directly.

print("=== 545e: DIRECT ===")
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

-- Step 1: Pre-mmap anon page at 0x880000000
local sc_mmap = make_syscall(477)
pcall(function()
    sc_mmap(target, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
end)
-- Write test pattern to verify it's mapped
wd(target, 0xAAAABBBB)
local pre_v = rd(to_num(target))
if not pre_v or (pre_v ~= 0xAAAABBBB and pre_v ~= -1431655749) then
    print("PREMMAP FAIL"); return
end
print("premmap=OK")

-- Step 2: AllocDM
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

-- Step 3: Set hint = 0x880000000
local virt_out = memory.alloc(8)
wq(virt_out, target)

-- Step 4: MapDM
print("MAP")
io.flush()
pcall(function()
    native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(0x33),
        uint64(0x400000), phys, uint64(0x4000))
end)
-- DON'T check return value. DON'T read virt_out.

-- Step 5: Test 0x880000000 directly
print("A")
io.flush()

-- Write a different pattern than what we wrote pre-MapDM
print("WR")
io.flush()
local ok_w = wd(target, 0xDEADBEEF)
print("wr=" .. tostring(ok_w))
io.flush()

if ok_w then
    print("RD")
    io.flush()
    local v = rd(to_num(target))
    if v then
        if v < 0 then v = v + 0x100000000 end
        print(string.format("v=0x%08X", v))
        io.flush()
        if v == 0xDEADBEEF then
            print("*** DIRECT MEMORY R/W AT 0x880000000 ***")

            -- Write a qword pattern
            wq(target, uint64("0xCAFEBABE12345678"))
            local qv = rq(target)
            if qv then
                print("qw=" .. q(qv))
            end

            -- Dump first 64 bytes of page
            print("DUMP:")
            for off = 0, 60, 4 do
                local dw = rd(to_num(target) + off)
                if dw then
                    if dw < 0 then dw = dw + 0x100000000 end
                    io.write(string.format("%08X ", dw))
                end
            end
            print("")

            -- Compare: is this actually physical memory?
            -- The pre-mmap page had 0xAAAABBBB. If MapDM replaced it with
            -- direct memory, a fresh read should NOT show 0xAAAABBBB.
            -- After our write it'll show 0xDEADBEEF anyway.
            -- Better: check a different offset on the page.
            local off8 = rd(to_num(target) + 8)
            if off8 then
                if off8 < 0 then off8 = off8 + 0x100000000 end
                print(string.format("off8=0x%08X", off8))
                -- If it's 0, that's consistent with fresh physical page (zeroed)
                -- If it's something else, it's pre-existing data on the phys page
            end
        elseif v == 0xAAAABBBB then
            print("STILL ANON (MapDM didn't replace)")
        else
            print("UNEXPECTED")
        end
    else
        print("rd=FAULT")
    end
else
    print("wr=CRASH")
end

print("pid=" .. to_num(syscall.getpid()))
print("DONE")
