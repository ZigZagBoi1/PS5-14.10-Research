-- CRASH_CLASS: LOW
-- PROBE 530n: Debug output corruption issue
--
-- 530k/l/m all show "77" then garbage after scanning pages.
-- This probe does minimal work to isolate the corruption source.

print("=== PROBE 530n ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sc_593 = mk(593)
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() sc_593(uint64(0), ib) end)
local tl = rd(N(ib) + 0x108) or 0
local th = rd(N(ib) + 0x10C) or 0
if tl < 0 then tl = tl + 0x100000000 end
if th < 0 then th = th + 0x100000000 end
local ts = rd(N(ib) + 0x110) or 0
if ts < 0 then ts = ts + 0x100000000 end

local eb_end = th * 0x100000000 + tl + ts
print(string.format("text_end=0x%X", eb_end))

-- Step 1: Just count readable pages (no content read)
print("step1: counting pages")
local count = 0
for p = 0, 127 do
    local addr = eb_end + p * 0x4000
    local v = rq(addr)
    if v ~= nil then count = count + 1 end
end
print(string.format("readable=%d", count))

-- Step 2: Print just the page numbers of readable pages
print("step2: page numbers")
local nums = {}
for p = 0, 127 do
    local addr = eb_end + p * 0x4000
    local v = rq(addr)
    if v ~= nil then table.insert(nums, tostring(p)) end
end
print(table.concat(nums, ","))

-- Step 3: For first readable page, read ONE qword and format it
print("step3: first page content")
local first_addr = nil
for p = 0, 127 do
    local addr = eb_end + p * 0x4000
    local v = rq(addr)
    if v ~= nil then
        first_addr = addr
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        print(string.format("page%d[0]=0x%08X%08X", p, vh, vl))
        break
    end
end

-- Step 4: Read gnm text info
print("step4: gnm info")
local gib = memory.alloc(0x200)
wd(N(gib), 0x160)
pcall(function() sc_593(uint64(56), gib) end)
local gtl = rd(N(gib) + 0x108) or 0
local gth = rd(N(gib) + 0x10C) or 0
if gtl < 0 then gtl = gtl + 0x100000000 end
if gth < 0 then gth = gth + 0x100000000 end
local gts = rd(N(gib) + 0x110) or 0
if gts < 0 then gts = gts + 0x100000000 end
print(string.format("gnm=0x%X%08X+0x%X", gth, gtl, gts))

-- Step 5: Scan ONLY first readable page for gnm pointers
print("step5: gnm in first page")
if first_addr then
    local gnm_count = 0
    for off = 0, 0x4000 - 8, 8 do
        local v = rq(first_addr + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vl < 0 then vl = vl + 0x100000000 end
            if vh == gth and vl >= gtl and vl < gtl + gts then
                gnm_count = gnm_count + 1
                if gnm_count <= 5 then
                    print(string.format("  off=0x%04X gnm+0x%04X", off, vl - gtl))
                end
            end
        end
    end
    print(string.format("gnm_in_page=%d", gnm_count))
end

print("=== DONE ===")
