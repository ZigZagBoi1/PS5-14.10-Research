-- CRASH_CLASS: SAFE (read-only)
-- PROBE 41s: deep scan eboot text for missing ROP gadgets
-- From 41r: first 300KB had pop_rax, pop_rsi, pop_rcx, jmp_rax, call_rax
-- MISSING: syscall;ret, pop rdi;ret, pop rdx;ret, stack pivot
-- Scan 0x48000-0x494000 in chunks, report ALL found gadgets
-- Strategy: scan in 0x48000 (288KB) chunks to stay within loader budget

print("=== PROBE 41s: DEEP EBOOT GADGET SCAN ===")
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

-- Get eboot text base (ASLR)
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

-- verify
local t = safe_rd(eboot)
if not t then print("NOT READABLE"); return end
print("")

--------------------------------------------------------------------
-- Scan from 0x48000 to end of text in one pass
-- Focus on the critical missing gadgets but track all
-- Use dword reads (4 bytes each) — ~0x120000 reads for full scan
-- That's a lot. Limit to 0x80000 reads max (~2MB coverage)
--------------------------------------------------------------------
local start_off = 0x48000
local end_off = math.min(text_size, 0x494000)
local max_reads = 0x80000

-- Track gadgets: store first 8 offsets of each type
local g = {
    syscall_ret = {},
    pop_rdi = {},
    pop_rsi = {},
    pop_rdx = {},
    pop_rcx = {},
    pop_rax = {},
    pop_r8 = {},
    jmp_rax = {},
    call_rax = {},
    leave_ret = {},
    xchg_rsp = {},
    -- also search for: pop rdi; pop rsi; ret (multi-pop)
    pop_rdi_rsi = {},
    -- int 0x80 (CD 80) — BSD syscall
    int80 = {},
    -- ret (C3) — just count
    ret_count = 0,
}

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

    -- syscall;ret (0F 05 C3) — THE critical gadget
    if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 and #g.syscall_ret < 8 then
        g.syscall_ret[#g.syscall_ret + 1] = off
    end
    if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 and #g.syscall_ret < 8 then
        g.syscall_ret[#g.syscall_ret + 1] = off + 1
    end

    -- pop rdi; ret (5F C3)
    if b0 == 0x5F and b1 == 0xC3 and #g.pop_rdi < 8 then
        g.pop_rdi[#g.pop_rdi + 1] = off
    end
    if b1 == 0x5F and b2 == 0xC3 and #g.pop_rdi < 8 then
        g.pop_rdi[#g.pop_rdi + 1] = off + 1
    end
    if b2 == 0x5F and b3 == 0xC3 and #g.pop_rdi < 8 then
        g.pop_rdi[#g.pop_rdi + 1] = off + 2
    end

    -- pop rdx; ret (5A C3)
    if b0 == 0x5A and b1 == 0xC3 and #g.pop_rdx < 8 then
        g.pop_rdx[#g.pop_rdx + 1] = off
    end
    if b1 == 0x5A and b2 == 0xC3 and #g.pop_rdx < 8 then
        g.pop_rdx[#g.pop_rdx + 1] = off + 1
    end
    if b2 == 0x5A and b3 == 0xC3 and #g.pop_rdx < 8 then
        g.pop_rdx[#g.pop_rdx + 1] = off + 2
    end

    -- pop rsi; ret (5E C3) — already have 2, get more
    if b0 == 0x5E and b1 == 0xC3 and #g.pop_rsi < 8 then
        g.pop_rsi[#g.pop_rsi + 1] = off
    end
    if b1 == 0x5E and b2 == 0xC3 and #g.pop_rsi < 8 then
        g.pop_rsi[#g.pop_rsi + 1] = off + 1
    end

    -- pop rax; ret (58 C3)
    if b0 == 0x58 and b1 == 0xC3 and #g.pop_rax < 8 then
        g.pop_rax[#g.pop_rax + 1] = off
    end
    if b1 == 0x58 and b2 == 0xC3 and #g.pop_rax < 8 then
        g.pop_rax[#g.pop_rax + 1] = off + 1
    end

    -- pop r8; ret (41 58 C3)
    if b0 == 0x41 and b1 == 0x58 and b2 == 0xC3 and #g.pop_r8 < 8 then
        g.pop_r8[#g.pop_r8 + 1] = off
    end
    if b1 == 0x41 and b2 == 0x58 and b3 == 0xC3 and #g.pop_r8 < 8 then
        g.pop_r8[#g.pop_r8 + 1] = off + 1
    end

    -- xchg rsp,rax (48 94) or (48 87 E4) or (48 87 C4)
    if b0 == 0x48 and b1 == 0x94 and #g.xchg_rsp < 8 then
        g.xchg_rsp[#g.xchg_rsp + 1] = off
    end
    if b0 == 0x48 and b1 == 0x87 and (b2 == 0xE4 or b2 == 0xC4) and #g.xchg_rsp < 8 then
        g.xchg_rsp[#g.xchg_rsp + 1] = off
    end

    -- mov rsp,rbp; pop rbp; ret = stack pivot via leave;ret (C9 C3)
    if b0 == 0xC9 and b1 == 0xC3 and #g.leave_ret < 8 then
        g.leave_ret[#g.leave_ret + 1] = off
    end
    if b1 == 0xC9 and b2 == 0xC3 and #g.leave_ret < 8 then
        g.leave_ret[#g.leave_ret + 1] = off + 1
    end

    -- jmp rax (FF E0)
    if b0 == 0xFF and b1 == 0xE0 and #g.jmp_rax < 8 then
        g.jmp_rax[#g.jmp_rax + 1] = off
    end

    -- int 0x80 (CD 80)
    if b0 == 0xCD and b1 == 0x80 and #g.int80 < 4 then
        g.int80[#g.int80 + 1] = off
    end

    -- ret count
    if b0 == 0xC3 then g.ret_count = g.ret_count + 1 end
end

print("reads: " .. reads .. " (" .. reads * 4 .. " bytes)")
print("coverage: eboot+0x" .. string.format("%X", start_off) .. " to +0x" .. string.format("%X", start_off + reads * 4))
print("")

--------------------------------------------------------------------
-- Report
--------------------------------------------------------------------
print("=== GADGET RESULTS ===")
print("")

local function report(name, list)
    print(string.format("%-18s: %d", name, #list))
    for j, off in ipairs(list) do
        print(string.format("  eboot+0x%06X", off))
    end
end

report("syscall;ret", g.syscall_ret)
report("pop rdi;ret", g.pop_rdi)
report("pop rdx;ret", g.pop_rdx)
report("pop rsi;ret", g.pop_rsi)
report("pop rax;ret", g.pop_rax)
report("pop rcx;ret", g.pop_rcx)
report("pop r8;ret", g.pop_r8)
report("leave;ret", g.leave_ret)
report("xchg rsp", g.xchg_rsp)
report("jmp rax", g.jmp_rax)
report("int 0x80", g.int80)
print(string.format("ret (total)       : %d", g.ret_count))
print("")

--------------------------------------------------------------------
-- Verify the critical ones
--------------------------------------------------------------------
print("=== VERIFICATION ===")
if #g.syscall_ret > 0 then
    local off = g.syscall_ret[1]
    local b0 = safe_rb(eboot + off)
    local b1 = safe_rb(eboot + off + 1)
    local b2 = safe_rb(eboot + off + 2)
    print(string.format("syscall;ret +0x%X: %02X %02X %02X %s",
        off, b0 or 0, b1 or 0, b2 or 0,
        (b0 == 0x0F and b1 == 0x05 and b2 == 0xC3) and "CONFIRMED" or "MISMATCH"))
else
    print("syscall;ret: NOT FOUND in scanned range")
    print("  need to scan 0x" .. string.format("%X", start_off + reads * 4) .. " to 0x" .. string.format("%X", end_off))
end

if #g.pop_rdi > 0 then
    local off = g.pop_rdi[1]
    local b0 = safe_rb(eboot + off)
    local b1 = safe_rb(eboot + off + 1)
    print(string.format("pop rdi;ret +0x%X: %02X %02X %s",
        off, b0 or 0, b1 or 0,
        (b0 == 0x5F and b1 == 0xC3) and "CONFIRMED" or "MISMATCH"))
else
    print("pop rdi;ret: NOT FOUND in scanned range")
end

if #g.pop_rdx > 0 then
    local off = g.pop_rdx[1]
    local b0 = safe_rb(eboot + off)
    local b1 = safe_rb(eboot + off + 1)
    print(string.format("pop rdx;ret +0x%X: %02X %02X %s",
        off, b0 or 0, b1 or 0,
        (b0 == 0x5A and b1 == 0xC3) and "CONFIRMED" or "MISMATCH"))
else
    print("pop rdx;ret: NOT FOUND in scanned range")
end
print("")

--------------------------------------------------------------------
-- Summary: do we have a complete ROP chain?
--------------------------------------------------------------------
print("=== ROP CHAIN STATUS ===")
local have_all = true
local chain = {
    {"pop rdi;ret", g.pop_rdi},
    {"pop rsi;ret", g.pop_rsi},
    {"pop rdx;ret", g.pop_rdx},
    {"pop rax;ret", g.pop_rax},
    {"syscall;ret", g.syscall_ret},
}
for _, c in ipairs(chain) do
    local status = #c[2] > 0 and string.format("YES (eboot+0x%X)", c[2][1]) or "MISSING"
    if #c[2] == 0 then have_all = false end
    print(string.format("  %-14s %s", c[1], status))
end
-- include the ones from 41r
print("  (also from 41r: pop_rsi at +0xD77D, pop_rax at +0x992)")
print("")
if have_all then
    print("*** COMPLETE ROP GADGET SET AVAILABLE ***")
else
    print("incomplete — need to scan remaining text")
end

print("")
print("=== PROBE 41s COMPLETE ===")
