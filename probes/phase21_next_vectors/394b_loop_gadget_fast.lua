-- CRASH_CLASS: LOW
-- PROBE 394b: fast scan for loop gadgets in eboot
--
-- Scan 64KB windows of eboot looking for leave;ret (C9 C3)
-- and pop rsp;ret (5C C3). Step by dword, check all byte positions.

print("=== PROBE 394b: gadget scan ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local base = eb_hi * 0x100000000 + eb_lo
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

-- Scan 4 windows of 16KB each = 64KB total, starting at different offsets
-- Function epilogues (leave;ret) should be common
local leave_hits = {}
local pop_rsp_hits = {}
local pop_rbp_hits = {}

local function scan_window(start_off, len)
    local prev_b3 = nil
    for off = start_off, start_off + len - 4, 4 do
        local d = rd(base + off)
        if d == nil then return end
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256

        -- Check boundary with previous dword
        if prev_b3 then
            if prev_b3 == 0xC9 and b0 == 0xC3 then
                if #leave_hits < 5 then table.insert(leave_hits, off - 1) end
            end
            if prev_b3 == 0x5C and b0 == 0xC3 then
                if #pop_rsp_hits < 5 then table.insert(pop_rsp_hits, off - 1) end
            end
            if prev_b3 == 0x5D and b0 == 0xC3 then
                if #pop_rbp_hits < 3 then table.insert(pop_rbp_hits, off - 1) end
            end
        end

        -- Check within this dword: positions 0-1, 1-2, 2-3
        -- leave;ret C9 C3
        if b0 == 0xC9 and b1 == 0xC3 then
            if #leave_hits < 5 then table.insert(leave_hits, off) end
        end
        if b1 == 0xC9 and b2 == 0xC3 then
            if #leave_hits < 5 then table.insert(leave_hits, off + 1) end
        end
        if b2 == 0xC9 and b3 == 0xC3 then
            if #leave_hits < 5 then table.insert(leave_hits, off + 2) end
        end

        -- pop rsp;ret 5C C3
        if b0 == 0x5C and b1 == 0xC3 then
            if #pop_rsp_hits < 5 then table.insert(pop_rsp_hits, off) end
        end
        if b1 == 0x5C and b2 == 0xC3 then
            if #pop_rsp_hits < 5 then table.insert(pop_rsp_hits, off + 1) end
        end
        if b2 == 0x5C and b3 == 0xC3 then
            if #pop_rsp_hits < 5 then table.insert(pop_rsp_hits, off + 2) end
        end

        -- pop rbp;ret 5D C3
        if b0 == 0x5D and b1 == 0xC3 then
            if #pop_rbp_hits < 3 then table.insert(pop_rbp_hits, off) end
        end
        if b1 == 0x5D and b2 == 0xC3 then
            if #pop_rbp_hits < 3 then table.insert(pop_rbp_hits, off + 1) end
        end
        if b2 == 0x5D and b3 == 0xC3 then
            if #pop_rbp_hits < 3 then table.insert(pop_rbp_hits, off + 2) end
        end

        prev_b3 = b3
    end
end

-- Scan windows: 0x1000-0x5000 (early funcs), 0x10000-0x14000, 0x50000-0x54000, 0x90000-0x94000
local windows = {0x1000, 0x10000, 0x50000, 0x90000}
for _, w in ipairs(windows) do
    print(string.format("scan +%X..+%X", w, w + 0x4000))
    scan_window(w, 0x4000)
    if #leave_hits > 0 then break end
end

print(string.format("leave;ret=%d pop_rsp;ret=%d pop_rbp;ret=%d",
    #leave_hits, #pop_rsp_hits, #pop_rbp_hits))

for _, off in ipairs(leave_hits) do
    print(string.format("  LEAVE +%06X", off))
end
for _, off in ipairs(pop_rsp_hits) do
    print(string.format("  POP_RSP +%06X", off))
end
for _, off in ipairs(pop_rbp_hits) do
    print(string.format("  POP_RBP +%06X", off))
end

print("=== 394b COMPLETE ===")
