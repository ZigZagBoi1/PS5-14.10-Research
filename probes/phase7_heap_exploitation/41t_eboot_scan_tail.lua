-- CRASH_CLASS: SAFE (read-only)
-- PROBE 41t: scan eboot text 0x248000-0x494000 for syscall;ret and pop rdx;ret
-- Continuation of 41s which covered 0x48000-0x248000

print("=== PROBE 41t: EBOOT TAIL SCAN ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local sc_dynlib_get_info = make_syscall(593)
local info_buf = memory.alloc(0x200)
for off = 0, 0x1F8, 4 do safe_wd(info_buf + off, 0) end
safe_wd(info_buf, 0x160)
pcall(function() sc_dynlib_get_info(uint64(0), info_buf) end)
local tb_lo = safe_rd(info_buf + 0x108)
local tb_hi = safe_rd(info_buf + 0x10C)
local ts_lo = safe_rd(info_buf + 0x110)
if not tb_lo or not tb_hi then print("FAILED"); return end

local text_hex = string.format("0x%X%08X", tb_hi, tb_lo)
local eboot = uint64(text_hex)
local text_size = ts_lo or 0x494000
print("eboot text: " .. text_hex .. " size=0x" .. string.format("%X", text_size))

local t = safe_rd(eboot)
if not t then print("NOT READABLE"); return end

local start_off = 0x248000
local end_off = math.min(text_size, 0x494000)
local max_reads = 0x80000

local g_syscall = {}
local g_pop_rdx = {}
local g_pop_rdi = {}
local g_pop_rsi = {}
local g_pop_rax = {}
local g_leave = {}
local g_xchg = {}

local reads = 0
print("scanning 0x" .. string.format("%X", start_off) .. " - 0x" .. string.format("%X", end_off))

for off = start_off, end_off - 4, 4 do
    local dw = safe_rd(eboot + off)
    if dw == nil then
        print("FAULT at eboot+0x" .. string.format("%X", off))
        break
    end
    reads = reads + 1
    if reads >= max_reads then break end

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- syscall;ret (0F 05 C3)
    if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 and #g_syscall < 8 then
        g_syscall[#g_syscall + 1] = off
    end
    if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 and #g_syscall < 8 then
        g_syscall[#g_syscall + 1] = off + 1
    end

    -- pop rdx; ret (5A C3)
    if b0 == 0x5A and b1 == 0xC3 and #g_pop_rdx < 8 then
        g_pop_rdx[#g_pop_rdx + 1] = off
    end
    if b1 == 0x5A and b2 == 0xC3 and #g_pop_rdx < 8 then
        g_pop_rdx[#g_pop_rdx + 1] = off + 1
    end
    if b2 == 0x5A and b3 == 0xC3 and #g_pop_rdx < 8 then
        g_pop_rdx[#g_pop_rdx + 1] = off + 2
    end

    -- Also track extras we might want
    if b0 == 0x5F and b1 == 0xC3 and #g_pop_rdi < 4 then
        g_pop_rdi[#g_pop_rdi + 1] = off
    end
    if b0 == 0x5E and b1 == 0xC3 and #g_pop_rsi < 4 then
        g_pop_rsi[#g_pop_rsi + 1] = off
    end
    if b0 == 0x58 and b1 == 0xC3 and #g_pop_rax < 4 then
        g_pop_rax[#g_pop_rax + 1] = off
    end
    if b0 == 0xC9 and b1 == 0xC3 and #g_leave < 4 then
        g_leave[#g_leave + 1] = off
    end
    if b0 == 0x48 and (b1 == 0x94 or (b1 == 0x87 and (b2 == 0xE4 or b2 == 0xC4))) and #g_xchg < 4 then
        g_xchg[#g_xchg + 1] = off
    end
end

print("reads: " .. reads .. " (" .. reads * 4 .. " bytes)")
print("coverage: eboot+0x" .. string.format("%X", start_off) .. " to +0x" .. string.format("%X", start_off + reads * 4))
print("")

print("=== RESULTS ===")
local function report(name, list)
    print(string.format("%-18s: %d", name, #list))
    for _, off in ipairs(list) do
        print(string.format("  eboot+0x%06X", off))
    end
end

report("syscall;ret", g_syscall)
report("pop rdx;ret", g_pop_rdx)
report("pop rdi;ret", g_pop_rdi)
report("pop rsi;ret", g_pop_rsi)
report("pop rax;ret", g_pop_rax)
report("leave;ret", g_leave)
report("xchg rsp", g_xchg)
print("")

-- Verify critical finds
print("=== VERIFICATION ===")
if #g_syscall > 0 then
    local off = g_syscall[1]
    local b0 = safe_rb(eboot + off)
    local b1 = safe_rb(eboot + off + 1)
    local b2 = safe_rb(eboot + off + 2)
    print(string.format("syscall;ret +0x%X: %02X %02X %02X %s",
        off, b0 or 0, b1 or 0, b2 or 0,
        (b0 == 0x0F and b1 == 0x05 and b2 == 0xC3) and "CONFIRMED" or "MISMATCH"))
end
if #g_pop_rdx > 0 then
    local off = g_pop_rdx[1]
    local b0 = safe_rb(eboot + off)
    local b1 = safe_rb(eboot + off + 1)
    print(string.format("pop rdx;ret +0x%X: %02X %02X %s",
        off, b0 or 0, b1 or 0,
        (b0 == 0x5A and b1 == 0xC3) and "CONFIRMED" or "MISMATCH"))
end
print("")

-- Full chain status combining all probes
print("=== FULL ROP CHAIN (all probes) ===")
local chain = {
    {"pop rdi;ret", "eboot+0xC9DFE (41s)"},
    {"pop rsi;ret", "eboot+0xD77D (41r)"},
    {"pop rdx;ret", #g_pop_rdx > 0 and string.format("eboot+0x%X (41t)", g_pop_rdx[1]) or "MISSING"},
    {"pop rax;ret", "eboot+0x992 (41r)"},
    {"syscall;ret", #g_syscall > 0 and string.format("eboot+0x%X (41t)", g_syscall[1]) or "MISSING"},
    {"jmp rax", "eboot+0x84C (41r)"},
    {"xchg rsp", "eboot+0x163874 (41s)"},
}
local complete = true
for _, c in ipairs(chain) do
    print(string.format("  %-14s %s", c[1], c[2]))
    if c[2] == "MISSING" then complete = false end
end
print("")
if complete then
    print("*** COMPLETE ROP GADGET SET ***")
else
    print("still missing gadgets — may need to scan data segments or other modules")
end
print("")
print("=== PROBE 41t COMPLETE ===")
