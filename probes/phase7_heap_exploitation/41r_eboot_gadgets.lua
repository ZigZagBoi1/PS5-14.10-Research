-- CRASH_CLASS: RISKY (eboot text read may crash if XO)
-- PROBE 41r: test eboot text readability and scan for gadgets
-- From 41q: system lib text is XO, data segments readable
-- eboot is at 0x3858C000 (game range, might be RX)
-- Also scan data segments of ALL modules for embedded code

print("=== PROBE 41r: EBOOT + DATA GADGET SCAN ===")
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

local sc_dynlib_get_list = make_syscall(592)
local sc_dynlib_get_info = make_syscall(593)

--------------------------------------------------------------------
-- STEP 1: Get eboot info
--------------------------------------------------------------------
print("--- STEP 1: EBOOT INFO ---")
local info_buf = memory.alloc(0x200)
for off = 0, 0x1F8, 4 do safe_wd(info_buf + off, 0) end
safe_wd(info_buf, 0x160)
pcall(function() sc_dynlib_get_info(uint64(0), info_buf) end)

local tb_lo = safe_rd(info_buf + 0x108)
local tb_hi = safe_rd(info_buf + 0x10C)
local ts_lo = safe_rd(info_buf + 0x110)
local db_lo = safe_rd(info_buf + 0x118)
local db_hi = safe_rd(info_buf + 0x11C)

if not tb_lo or not tb_hi then
    print("FAILED to get eboot info")
    return
end

local text_hex = string.format("0x%X%08X", tb_hi, tb_lo)
local data_hex = string.format("0x%X%08X", db_hi or 0, db_lo or 0)
print("eboot text: " .. text_hex .. " size=0x" .. string.format("%X", ts_lo or 0))
print("eboot data: " .. data_hex)
print("")

--------------------------------------------------------------------
-- STEP 2: Test eboot text readability
-- eboot is at 0x03_858C000 — in game VA range, likely RX not XO
--------------------------------------------------------------------
print("--- STEP 2: EBOOT TEXT READ TEST ---")
local eboot_text = uint64(text_hex)
local test_dw = safe_rd(eboot_text)
if test_dw then
    print("EBOOT TEXT IS READABLE: " .. string.format("0x%08X", test_dw))
    -- show first 16 bytes
    local bytes = {}
    for i = 0, 15 do
        local b = safe_rb(eboot_text + i)
        bytes[#bytes + 1] = b and string.format("%02X", b) or "??"
    end
    print("first 16 bytes: " .. table.concat(bytes, " "))
else
    print("eboot text is XO/FAULT — cannot read")
    print("falling back to data-only scan")
end
print("")

--------------------------------------------------------------------
-- STEP 3: Gadget scan in eboot text (if readable)
-- Scan 0x48000 bytes (first ~300KB), report all gadgets
--------------------------------------------------------------------
if test_dw then
    print("--- STEP 3: EBOOT GADGET SCAN ---")

    local scan_size = math.min(ts_lo or 0x48000, 0x48000)
    local gadgets = {}
    local types = {
        "syscall_ret", "pop_rdi", "pop_rsi", "pop_rdx",
        "pop_rcx", "pop_rax", "pop_r8", "pop_rbp",
        "jmp_rax", "call_rax", "leave_ret",
        "mov_rdi_rax", "xchg_rsp"
    }
    for _, t in ipairs(types) do gadgets[t] = {} end

    local reads = 0
    for off = 0, scan_size - 4, 4 do
        local dw = safe_rd(eboot_text + off)
        if dw == nil then break end
        reads = reads + 1

        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        -- syscall;ret (0F 05 C3)
        if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
            gadgets.syscall_ret[#gadgets.syscall_ret + 1] = off
        end
        if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 then
            gadgets.syscall_ret[#gadgets.syscall_ret + 1] = off + 1
        end

        -- pop reg; ret patterns
        local pop_patterns = {
            {byte=0x5F, name="pop_rdi"},
            {byte=0x5E, name="pop_rsi"},
            {byte=0x5A, name="pop_rdx"},
            {byte=0x59, name="pop_rcx"},
            {byte=0x58, name="pop_rax"},
            {byte=0x5D, name="pop_rbp"},
        }
        for _, pp in ipairs(pop_patterns) do
            if b0 == pp.byte and b1 == 0xC3 then
                gadgets[pp.name][#gadgets[pp.name] + 1] = off
            end
            if b1 == pp.byte and b2 == 0xC3 then
                gadgets[pp.name][#gadgets[pp.name] + 1] = off + 1
            end
            if b2 == pp.byte and b3 == 0xC3 then
                gadgets[pp.name][#gadgets[pp.name] + 1] = off + 2
            end
        end

        -- pop r8; ret (41 58 C3)
        if b0 == 0x41 and b1 == 0x58 and b2 == 0xC3 then
            gadgets.pop_r8[#gadgets.pop_r8 + 1] = off
        end
        if b1 == 0x41 and b2 == 0x58 and b3 == 0xC3 then
            gadgets.pop_r8[#gadgets.pop_r8 + 1] = off + 1
        end

        -- jmp rax (FF E0), call rax (FF D0)
        if b0 == 0xFF and b1 == 0xE0 then
            gadgets.jmp_rax[#gadgets.jmp_rax + 1] = off
        end
        if b1 == 0xFF and b2 == 0xE0 then
            gadgets.jmp_rax[#gadgets.jmp_rax + 1] = off + 1
        end
        if b0 == 0xFF and b1 == 0xD0 then
            gadgets.call_rax[#gadgets.call_rax + 1] = off
        end

        -- leave;ret (C9 C3)
        if b0 == 0xC9 and b1 == 0xC3 then
            gadgets.leave_ret[#gadgets.leave_ret + 1] = off
        end
        if b1 == 0xC9 and b2 == 0xC3 then
            gadgets.leave_ret[#gadgets.leave_ret + 1] = off + 1
        end

        -- mov rdi,rax;ret (48 89 C7 C3) — 4 bytes
        if b0 == 0x48 and b1 == 0x89 and b2 == 0xC7 and b3 == 0xC3 then
            gadgets.mov_rdi_rax[#gadgets.mov_rdi_rax + 1] = off
        end

        -- xchg rsp,rax (48 94)
        if b0 == 0x48 and b1 == 0x94 then
            gadgets.xchg_rsp[#gadgets.xchg_rsp + 1] = off
        end

        -- limit scan to avoid overwhelming the loader
        if reads >= 0x12000 then break end
    end

    print("scanned: " .. reads * 4 .. " bytes")
    print("")
    print("GADGET CATALOG:")
    for _, t in ipairs(types) do
        local list = gadgets[t]
        local label = t:gsub("_", " ")
        print(string.format("  %-16s: %d found", label, #list))
        for j = 1, math.min(#list, 5) do
            print(string.format("    eboot+0x%06X", list[j]))
        end
    end
    print("")

    -- verify top gadgets
    print("VERIFICATION:")
    if #gadgets.syscall_ret > 0 then
        local off = gadgets.syscall_ret[1]
        local b0 = safe_rb(eboot_text + off)
        local b1 = safe_rb(eboot_text + off + 1)
        local b2 = safe_rb(eboot_text + off + 2)
        print(string.format("  syscall;ret at +0x%X: %02X %02X %02X %s",
            off, b0 or 0, b1 or 0, b2 or 0,
            (b0 == 0x0F and b1 == 0x05 and b2 == 0xC3) and "OK" or "BAD"))
    end
    if #gadgets.pop_rdi > 0 then
        local off = gadgets.pop_rdi[1]
        local b0 = safe_rb(eboot_text + off)
        local b1 = safe_rb(eboot_text + off + 1)
        print(string.format("  pop rdi;ret at +0x%X: %02X %02X %s",
            off, b0 or 0, b1 or 0,
            (b0 == 0x5F and b1 == 0xC3) and "OK" or "BAD"))
    end
    if #gadgets.pop_rax > 0 then
        local off = gadgets.pop_rax[1]
        local b0 = safe_rb(eboot_text + off)
        local b1 = safe_rb(eboot_text + off + 1)
        print(string.format("  pop rax;ret at +0x%X: %02X %02X %s",
            off, b0 or 0, b1 or 0,
            (b0 == 0x58 and b1 == 0xC3) and "OK" or "BAD"))
    end
else
    print("--- STEP 3: SKIPPED (text not readable) ---")
end
print("")

--------------------------------------------------------------------
-- STEP 4: Scan libkernel DATA for embedded code
-- PLT stubs or trampolines may exist in data segment
--------------------------------------------------------------------
print("--- STEP 4: LIBKERNEL DATA SCAN ---")
do
    -- get libkernel data base
    for off2 = 0, 0x1F8, 4 do safe_wd(info_buf + off2, 0) end
    safe_wd(info_buf, 0x160)
    pcall(function() sc_dynlib_get_info(uint64(0x2001), info_buf) end)
    local kd_lo = safe_rd(info_buf + 0x118)
    local kd_hi = safe_rd(info_buf + 0x11C)
    local kd_sz = safe_rd(info_buf + 0x120)
    if kd_lo and kd_hi then
        local kd_hex = string.format("0x%X%08X", kd_hi, kd_lo)
        local kd_addr = uint64(kd_hex)
        local test = safe_rd(kd_addr)
        if test then
            print("libkernel data at " .. kd_hex .. " sz=0x" .. string.format("%X", kd_sz or 0))
            local sr = 0
            local prdi = 0
            local prax = 0
            local interesting = {}
            local max_scan = math.min(kd_sz or 0x10000, 0x10000)
            for off = 0, max_scan - 4, 4 do
                local dw = safe_rd(kd_addr + off)
                if dw == nil then break end
                local b0 = dw % 256
                local b1 = math.floor(dw / 256) % 256
                local b2 = math.floor(dw / 65536) % 256
                if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
                    sr = sr + 1
                    interesting[#interesting + 1] = string.format("+0x%X: syscall;ret", off)
                end
                if b0 == 0x5F and b1 == 0xC3 then prdi = prdi + 1 end
                if b0 == 0x58 and b1 == 0xC3 then prax = prax + 1 end
            end
            print(string.format("  syscall;ret=%d pop_rdi=%d pop_rax=%d", sr, prdi, prax))
            for _, s in ipairs(interesting) do print("    " .. s) end
        else
            print("libkernel data NOT readable")
        end
    end
end
print("")

print("=== PROBE 41r COMPLETE ===")
