-- CRASH_CLASS: LOW
-- PROBE 588: Constant drain — libkernel + libc offset verification
--
-- Compares 13.60 hypothesis offsets against actual module bases on 14.10.
-- Uses the working 56g2 pattern for dynlib_get_info enumeration.
--
-- Three verification methods:
--   1. Address math: cross-reference libc_addrofs with dynlib_get_info bases
--   2. Data read: read values at base+offset for data-segment constants
--   3. Function call: sceKernelGetCurrentCpu (0 args, should return 0-7)

print("=== PROBE 588: CONSTANT DRAIN LK+LC ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end
local function rb(buf, off)
    local addr = N(buf) + (off - off % 4)
    local dw = rd(addr)
    if not dw then return 0 end
    local shift = (off % 4) * 8
    return math.floor(dw / (2 ^ shift)) % 256
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

-- ============================================================
-- SECTION A: Enumerate modules via dynlib_get_info (593)
-- Pattern from working probe 56g2
-- ============================================================
print("")
print("--- A: MODULE ENUMERATION ---")

local sc593 = mk(593)
local info = memory.alloc(0x200)
local modules = {}

for handle = 0, 50 do
    -- Zero the buffer before each call
    for i = 0, 0x1FF, 4 do wd(N(info) + i, 0) end
    wd(N(info), 0x160)

    local ok, ret = pcall(function() return sc593(uint64(handle), info) end)
    if ok and N(ret) == 0 then
        -- Read name from offset 0x08
        local name_bytes = {}
        for j = 0, 255 do
            local b = rb(info, 0x08 + j)
            if b == 0 then break end
            name_bytes[#name_bytes + 1] = string.char(b)
        end
        local name = table.concat(name_bytes)

        -- Read text base (uint64 at +0x108)
        local tlo = rd(N(info) + 0x108) or 0
        local thi = rd(N(info) + 0x10C) or 0
        if tlo < 0 then tlo = tlo + 0x100000000 end
        if thi < 0 then thi = thi + 0x100000000 end
        local text_size = rd(N(info) + 0x110) or 0
        if text_size < 0 then text_size = text_size + 0x100000000 end
        local text_prot = rd(N(info) + 0x114) or 0

        -- Read data base (uint64 at +0x118)
        local dlo = rd(N(info) + 0x118) or 0
        local dhi = rd(N(info) + 0x11C) or 0
        if dlo < 0 then dlo = dlo + 0x100000000 end
        if dhi < 0 then dhi = dhi + 0x100000000 end
        local data_size = rd(N(info) + 0x120) or 0
        if data_size < 0 then data_size = data_size + 0x100000000 end
        local data_prot = rd(N(info) + 0x124) or 0

        local text_base = uint64(string.format("0x%X%08X", thi, tlo))
        local data_base = uint64(string.format("0x%X%08X", dhi, dlo))

        modules[#modules+1] = {
            handle = handle, name = name,
            text_base = text_base, tlo = tlo, thi = thi,
            text_size = text_size, text_prot = text_prot,
            data_base = data_base, dlo = dlo, dhi = dhi,
            data_size = data_size, data_prot = data_prot,
        }

        print(string.format("  [%2d] %-40s text=0x%X%08X(sz=0x%X,p=%d) data=0x%X%08X(sz=0x%X,p=%d)",
            handle, name, thi, tlo, text_size, text_prot, dhi, dlo, data_size, data_prot))
    end
end

print("  total=" .. #modules)

-- ============================================================
-- SECTION B: Find libkernel and libc modules
-- ============================================================
print("")
print("--- B: IDENTIFY KEY MODULES ---")

local lk_mod = nil
local lc_mod = nil
for _, m in ipairs(modules) do
    local nl = m.name:lower()
    if nl:find("libkernel") and not lk_mod then
        lk_mod = m
        print("  libkernel: h=" .. m.handle .. " name=" .. m.name)
    end
    if (nl:find("libscelibc") or nl:find("libc_internal")) and not lc_mod then
        lc_mod = m
        print("  libc: h=" .. m.handle .. " name=" .. m.name)
    end
end

if not lk_mod then print("  WARNING: libkernel not found") end
if not lc_mod then print("  WARNING: libc not found") end

-- ============================================================
-- SECTION C: libc offset verification via libc_addrofs cross-reference
-- ============================================================
print("")
print("--- C: LIBC ADDROFS CROSS-REFERENCE ---")

local HYPO_LC = {
    {name="setjmp",  offset=0x5D990},
    {name="longjmp", offset=0x5D9E0},
    {name="memset",  offset=0x14700},
}

if libc_addrofs then
    for k, v in pairs(libc_addrofs) do
        print(string.format("  libc_addrofs.%s = %s", k, fmt64(v)))
    end

    if lc_mod then
        print("")
        print("  libc text_base = " .. fmt64(lc_mod.text_base))

        for _, h in ipairs(HYPO_LC) do
            local expected = lc_mod.text_base + uint64(h.offset)
            local actual = libc_addrofs[h.name]
            if actual then
                local exp_h, exp_l = get_hi_lo(expected)
                local act_h, act_l = get_hi_lo(actual)
                local match = (exp_h == act_h and exp_l == act_l)
                print(string.format("  %s: expected=%s actual=%s %s",
                    h.name, fmt64(expected), fmt64(actual),
                    match and "MATCH" or "MISMATCH"))
                if not match then
                    local act_num = act_h * 0x100000000 + act_l
                    local base_h, base_l = get_hi_lo(lc_mod.text_base)
                    local base_num = base_h * 0x100000000 + base_l
                    local real_offset = act_num - base_num
                    print(string.format("    real_offset=0x%X (hypothesis=0x%X delta=%d)",
                        real_offset, h.offset, real_offset - h.offset))
                end
            else
                print(string.format("  %s: not in libc_addrofs", h.name))
            end
        end

        -- Reverse: compute base from each known function
        print("")
        print("  -- Reverse base computation --")
        for _, h in ipairs(HYPO_LC) do
            local actual = libc_addrofs[h.name]
            if actual then
                local act_h, act_l = get_hi_lo(actual)
                local act_num = act_h * 0x100000000 + act_l
                local computed_base = act_num - h.offset
                print(string.format("  base_from_%s = 0x%X (via offset 0x%X)",
                    h.name, computed_base, h.offset))
            end
        end
    else
        -- No libc module found, but we can still do reverse base computation
        print("  libc module not identified, doing reverse base computation only")
        for _, h in ipairs(HYPO_LC) do
            local actual = libc_addrofs[h.name]
            if actual then
                local act_h, act_l = get_hi_lo(actual)
                local act_num = act_h * 0x100000000 + act_l
                local computed_base = act_num - h.offset
                print(string.format("  base_from_%s = 0x%X (via offset 0x%X)",
                    h.name, computed_base, h.offset))
            end
        end
    end
else
    print("  libc_addrofs is nil")
end

-- ============================================================
-- SECTION D: libkernel offset verification
-- ============================================================
print("")
print("--- D: LIBKERNEL OFFSET VERIFICATION ---")

local HYPO_LK = {
    {name="sceKernelGetCurrentCpu", offset=0x1200,  type="code"},
    {name="worker_wait_return",     offset=0x1FD01, type="code"},
    {name="pthread_create_name_np", offset=0x21890, type="code"},
    {name="pthread_join",           offset=0x229A0, type="code"},
    {name="pthread_exit",           offset=0x21C20, type="code"},
    {name="sleep",                  offset=0x27F00, type="code"},
    {name="__stack_chk_guard",      offset=0x751D0, type="data"},
    {name="_thread_list",           offset=0x6C218, type="data"},
}

if lk_mod then
    print("  libkernel text_base = " .. fmt64(lk_mod.text_base))
    print("  libkernel text_size = 0x" .. string.format("%X", lk_mod.text_size))
    print("  libkernel data_base = " .. fmt64(lk_mod.data_base))
    print("  libkernel data_size = 0x" .. string.format("%X", lk_mod.data_size))

    local lk_base_h, lk_base_l = get_hi_lo(lk_mod.text_base)
    local lk_base_num = lk_base_h * 0x100000000 + lk_base_l
    local lk_dbase_h, lk_dbase_l = get_hi_lo(lk_mod.data_base)
    local lk_dbase_num = lk_dbase_h * 0x100000000 + lk_dbase_l
    local lk_data_offset = lk_dbase_num - lk_base_num

    print(string.format("  data_segment_offset_from_text = 0x%X", lk_data_offset))

    for _, h in ipairs(HYPO_LK) do
        local target = lk_mod.text_base + uint64(h.offset)
        local in_text = (h.offset < lk_mod.text_size)
        local in_data = (h.offset >= lk_data_offset and h.offset < lk_data_offset + lk_mod.data_size)

        local segment = "UNMAPPED"
        if in_text then segment = "TEXT" end
        if in_data then segment = "DATA" end

        print(string.format("  %s: offset=0x%X addr=%s segment=%s type=%s",
            h.name, h.offset, fmt64(target), segment, h.type))

        -- Only read DATA-type offsets in DATA segment (p=0x3, readable)
        -- NEVER read from TEXT segment — system lib .text is XO, kills past pcall
        if h.type == "data" and in_data then
            local val = rq(target)
            if val then
                print(string.format("    READ_OK value=%s", fmt64(val)))
            else
                print("    READ_FAIL")
            end
        elseif h.type == "data" and in_text then
            print("    SKIP_READ (data symbol in XO text segment)")
        end
    end
else
    print("  libkernel not found, skipping")
end

-- ============================================================
-- SECTION E: sceKernelGetCurrentCpu function call test
-- ============================================================
print("")
print("--- E: FUNCTION CALL TEST ---")

if lk_mod and native and native.fcall_with_rax then
    local cpu_addr = lk_mod.text_base + uint64(0x1200)
    print("  sceKernelGetCurrentCpu target = " .. fmt64(cpu_addr))

    local ok, ret = pcall(function()
        return native.fcall_with_rax(cpu_addr, 0)
    end)
    if ok then
        local rv = N(ret)
        print(string.format("  result: val=%d (0x%X)", rv, rv))
        if rv >= 0 and rv <= 7 then
            print("  VERDICT: sceKernelGetCurrentCpu offset 0x1200 is LIVE on 14.10")
        else
            print("  VERDICT: returned " .. rv .. " (not 0-7), offset may be WRONG")
        end
    else
        print("  fcall FAILED: " .. tostring(ret))
        print("  VERDICT: offset 0x1200 is likely WRONG")
    end
else
    if not lk_mod then
        print("  libkernel not found, skipping")
    else
        print("  native.fcall_with_rax not available, skipping")
    end
end

-- ============================================================
-- SECTION F: Cross-reference libc_addrofs with ALL modules
-- ============================================================
print("")
print("--- F: MODULE MEMBERSHIP ---")

if libc_addrofs then
    for fname, faddr in pairs(libc_addrofs) do
        local fa_h, fa_l = get_hi_lo(faddr)
        local fa_num = fa_h * 0x100000000 + fa_l
        local found = false
        for _, m in ipairs(modules) do
            local tb_h, tb_l = get_hi_lo(m.text_base)
            local tb_num = tb_h * 0x100000000 + tb_l
            local td_h, td_l = get_hi_lo(m.data_base)
            local td_num = td_h * 0x100000000 + td_l
            if fa_num >= tb_num and fa_num < tb_num + m.text_size then
                local off = fa_num - tb_num
                print(string.format("  %s -> %s .text +0x%X (h=%d)",
                    fname, m.name, off, m.handle))
                found = true
                break
            elseif td_num > 0 and fa_num >= td_num and fa_num < td_num + m.data_size then
                local off = fa_num - td_num
                print(string.format("  %s -> %s .data +0x%X (h=%d)",
                    fname, m.name, off, m.handle))
                found = true
                break
            end
        end
        if not found then
            print(string.format("  %s = %s -> NO MODULE MATCH", fname, fmt64(faddr)))
        end
    end
end

-- ============================================================
-- SECTION G: Canary
-- ============================================================
print("")
local ok_canary = N(native.fcall_with_rax(stub, 20)) == pid
print("canary=" .. tostring(ok_canary))
print("=== PROBE 588 COMPLETE ===")
