-- CRASH_CLASS: LOW
-- PROBE 123b: Eboot scan 2MB-4.6MB for syscall and stack pivot gadgets
--
-- Context: 118a/122b scanned first ~2MB. Eboot is ~4.6MB. The remaining
-- 2.6MB is unscanned. We need:
--   1. syscall (0F 05) instructions — especially "mov eax,N; syscall; ret"
--   2. Stack pivot gadgets (leave;ret, xchg rax,rsp, etc.)
--   3. More pop gadgets, write gadgets
--
-- Section A: Scan 0x200000-0x300000 for 0F 05 (syscall)
-- Section B: Scan 0x300000-0x400000
-- Section C: Scan 0x400000-0x4A0000 (eboot may end ~0x480000)
-- Section D: For each syscall found, dump ±32 bytes context

print("=== PROBE 123b: EBOOT SCAN 2MB-4.6MB ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local function get_eboot_base()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108)
    local hi = safe_rd(info + 0x10C)
    if lo and hi then
        return uint64(string.format("0x%X%08X", hi, lo)), hi, lo
    end
    return nil, 0, 0
end

collectgarbage("stop")

local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
print(string.format("[*] eboot base: 0x%08X_%08X", eboot_hi, eboot_lo))

if not eboot_base then
    print("ABORT: no eboot base")
    return
end

local function eboot_off_addr(off)
    local lo = eboot_lo + off
    local hi = eboot_hi
    if lo >= 0x100000000 then
        hi = hi + 1
        lo = lo - 0x100000000
    end
    return uint64(string.format("0x%X%08X", hi, lo))
end

-- Find eboot end by scanning for unreadable pages
print("[*] Finding eboot .text end...")
local eboot_end = 0x200000
for off = 0x200000, 0x500000, 0x1000 do
    local addr = eboot_off_addr(off)
    local v = safe_rd(addr)
    if v == nil then
        eboot_end = off
        break
    end
    eboot_end = off + 0x1000
end
print(string.format("[*] eboot readable up to +0x%X (%d KB)", eboot_end, eboot_end / 1024))

-- Scan for syscall (0F 05) in unscanned range
print("")
print("--- Scanning for syscall (0F 05) from 0x200000 ---")
print("")

local syscall_hits = {}
local scan_start = 0x200000
local scan_end_actual = eboot_end

for off = scan_start, scan_end_actual - 4, 4 do
    local addr = eboot_off_addr(off)
    local dw = safe_rd(addr)
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256
        -- Check each byte position
        if b0 == 0x0F and b1 == 0x05 then
            syscall_hits[#syscall_hits + 1] = off
        end
        if b1 == 0x0F and b2 == 0x05 then
            syscall_hits[#syscall_hits + 1] = off + 1
        end
        if b2 == 0x0F and b3 == 0x05 then
            syscall_hits[#syscall_hits + 1] = off + 2
        end
        -- Cross-dword boundary: check b3 == 0x0F, next dword b0 == 0x05
        if b3 == 0x0F then
            local addr2 = eboot_off_addr(off + 4)
            local dw2 = safe_rd(addr2)
            if dw2 and (dw2 % 256) == 0x05 then
                syscall_hits[#syscall_hits + 1] = off + 3
            end
        end
    end
    -- Progress every 256KB
    if off % 0x40000 == 0 and off > scan_start then
        print(string.format("  ... scanned to +0x%X (%d hits so far)", off, #syscall_hits))
    end
end

print(string.format("\n[*] Found %d syscall instructions in 0x%X-0x%X range",
    #syscall_hits, scan_start, scan_end_actual))

-- Dump context around each hit
for i, off in ipairs(syscall_hits) do
    print(string.format("\n--- SYSCALL #%d at eboot+0x%X ---", i, off))

    -- Read ±16 bytes (4 dwords before, 4 after)
    print("  Context bytes (before → after):")
    local ctx = {}
    for delta = -16, 16, 4 do
        local addr = eboot_off_addr(off + delta)
        local dw = safe_rd(addr)
        ctx[#ctx + 1] = string.format("%+d:0x%08X", delta, dw or 0)
    end
    print("  " .. table.concat(ctx, " "))

    -- Check for "mov eax, N; syscall" pattern
    -- mov eax, imm32 = B8 XX XX XX XX (5 bytes before syscall)
    local pre5 = eboot_off_addr(off - 5)
    local pre5_dw = safe_rd(pre5)
    if pre5_dw then
        local pre5_b0 = pre5_dw % 256
        if pre5_b0 == 0xB8 then
            -- B8 at -5 means mov eax, imm32
            local syscall_num_lo = math.floor(pre5_dw / 256) % 256
            local syscall_num_hi_lo = math.floor(pre5_dw / 65536) % 256
            local syscall_num_hi_hi = math.floor(pre5_dw / 16777216) % 256
            local pre1 = eboot_off_addr(off - 1)
            local pre1_dw = safe_rd(pre1)
            local syscall_num_top = pre1_dw and (pre1_dw % 256) or 0
            local syscall_num = syscall_num_lo + syscall_num_hi_lo * 256 +
                syscall_num_hi_hi * 65536 + syscall_num_top * 16777216
            print(string.format("  *** MOV EAX, %d (0x%X); SYSCALL at eboot+0x%X ***",
                syscall_num, syscall_num, off - 5))

            -- Check what follows syscall
            local post = eboot_off_addr(off + 2)
            local post_dw = safe_rd(post)
            if post_dw then
                local post_b0 = post_dw % 256
                if post_b0 == 0xC3 then
                    print(string.format("  *** GOLD: mov eax,%d; syscall; ret at eboot+0x%X ***",
                        syscall_num, off - 5))
                end
            end
        end
    end

    -- Check for xor eax,eax; syscall (31 C0 0F 05)
    local pre2 = eboot_off_addr(off - 2)
    local pre2_dw = safe_rd(pre2)
    if pre2_dw then
        local lo16 = pre2_dw % 65536
        if lo16 == 0xC031 then
            print(string.format("  *** XOR EAX,EAX; SYSCALL (sys 0) at eboot+0x%X ***", off - 2))
        end
    end

    -- Check what follows: ret (C3)?
    local post2 = eboot_off_addr(off + 2)
    local post2_dw = safe_rd(post2)
    if post2_dw then
        local post_b0 = post2_dw % 256
        if post_b0 == 0xC3 then
            print("  Followed by RET — clean return after syscall")
        elseif post_b0 == 0x48 or post_b0 == 0x89 then
            print(string.format("  Followed by 0x%02X — likely register save/cleanup", post_b0))
        end
    end
end

-- Also scan for leave;ret (C9 C3) and pop rsp;ret (5C C3) in new range
print("")
print("--- Scanning new range for stack pivot gadgets ---")

local pivot_hits = {}
for off = scan_start, scan_end_actual - 4, 4 do
    local addr = eboot_off_addr(off)
    local dw = safe_rd(addr)
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        -- leave;ret = C9 C3
        if b0 == 0xC9 and b1 == 0xC3 then
            pivot_hits[#pivot_hits + 1] = {off, "leave;ret"}
        end
        if b1 == 0xC9 and b2 == 0xC3 then
            pivot_hits[#pivot_hits + 1] = {off+1, "leave;ret"}
        end
        if b2 == 0xC9 and b3 == 0xC3 then
            pivot_hits[#pivot_hits + 1] = {off+2, "leave;ret"}
        end

        -- xchg rax,rsp = 48 94
        if b0 == 0x48 and b1 == 0x94 then
            pivot_hits[#pivot_hits + 1] = {off, "xchg rax,rsp"}
        end
        if b1 == 0x48 and b2 == 0x94 then
            pivot_hits[#pivot_hits + 1] = {off+1, "xchg rax,rsp"}
        end

        -- pop rsp (5C) followed by C3
        if b0 == 0x5C and b1 == 0xC3 then
            pivot_hits[#pivot_hits + 1] = {off, "pop rsp;ret"}
        end
        if b1 == 0x5C and b2 == 0xC3 then
            pivot_hits[#pivot_hits + 1] = {off+1, "pop rsp;ret"}
        end
    end
end

if #pivot_hits > 0 then
    print(string.format("[*] Found %d pivot gadgets:", #pivot_hits))
    for _, hit in ipairs(pivot_hits) do
        print(string.format("  eboot+0x%X: %s", hit[1], hit[2]))
    end
else
    print("[*] No pivot gadgets in extended range")
end

print("")
print("=== PROBE 123b COMPLETE ===")
