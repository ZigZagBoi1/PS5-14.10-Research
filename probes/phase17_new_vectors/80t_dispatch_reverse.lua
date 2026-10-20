-- CRASH_CLASS: LOW
-- PROBE 80t: Reverse-engineer the loader's syscall dispatch
--
-- 47a showed the dispatch mechanism:
--   fn_addr, syscall_no, rdi, rsi, rdx, rcx, r8, r9 are heap slots
--   __call function at a heap CClosure address
--   The C function pointer inside that CClosure points to eboot .text
--
-- If we find the C function address and understand its ABI, a thread
-- could call it directly (via call rax or jmp) to invoke syscalls.
--
-- Plan:
--   A) Read the __call CClosure's C function pointer (+0x20)
--   B) Read fn_addr slot contents and arg_addr layout
--   C) Scan eboot for call rax / jmp rax gadgets
--   D) Scan for int 0x80 (legacy syscall)
--   E) Dump bytes around each of the 4 syscall instructions

print("=== PROBE 80t: DISPATCH REVERSE ENGINEERING ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

syscall.resolve({ sc_getpid = 20 })
local pid = syscall.sc_getpid():tonumber()
print("[*] pid=" .. pid)

-- Get eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eboot = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("[*] eboot=" .. q(eboot))

-- =================================================================
-- SECTION A: Read the __call CClosure's C function pointer
-- =================================================================
print("")
print("=== [A] __CALL C FUNCTION POINTER ===")

-- Get metatable of syscall.pipe
local mt = getmetatable(syscall.pipe)
if mt then
    print("[A] metatable found")
    if mt.__call then
        print("[A] __call exists: " .. type(mt.__call))
        local call_str = tostring(mt.__call)
        print("[A] __call tostring: " .. call_str)

        -- The __call is a CClosure. Its C function pointer is at +0x20
        -- Parse the address from tostring
        local addr_str = call_str:match("(0x[0-9a-fA-F]+)")
        if addr_str then
            local call_addr = uint64(addr_str)
            print("[A] CClosure addr: " .. q(call_addr))

            -- Read C function pointer at +0x20
            local cfunc = rq(call_addr + 0x20)
            if cfunc then
                print("[A] C function ptr (+0x20): " .. q(cfunc))

                -- Check if it's in eboot range
                local cf_h, cf_l = 0, 0
                if type(cfunc) == "table" and cfunc.h then
                    cf_h = cfunc.h; cf_l = cfunc.l
                else cf_l = to_num(cfunc) end

                local eb_h, eb_l = 0, 0
                if type(eboot) == "table" and eboot.h then
                    eb_h = eboot.h; eb_l = eboot.l
                else eb_l = to_num(eboot) end

                if cf_h == eb_h then
                    local offset = cf_l - eb_l
                    if offset >= 0 and offset < 0x200000 then
                        print(string.format("[A] *** IN EBOOT .text at +0x%X ***", offset))

                        -- Dump 64 bytes at the function entry
                        local bytes = ""
                        for i = 0, 63 do
                            local b = rb(cfunc + i)
                            if b then bytes = bytes .. string.format("%02X ", b)
                            else bytes = bytes .. "?? " end
                            if i % 16 == 15 then
                                print("  +" .. string.format("%02X", i - 15) .. ": " .. bytes)
                                bytes = ""
                            end
                        end
                    end
                end
            end

            -- Also read other CClosure fields
            print("")
            print("[A] CClosure dump (first 64 bytes):")
            for off = 0, 0x38, 8 do
                local v = rq(call_addr + off)
                if v then
                    print(string.format("  +0x%02X: %s", off, q(v)))
                end
            end
        end
    end

    -- Also check create_initial_chain and new
    if mt.__index then
        print("")
        print("[A] __index table:")
        for k, v in pairs(mt.__index) do
            print("  " .. tostring(k) .. " = " .. tostring(v))
            if type(v) == "function" then
                local faddr_str = tostring(v):match("(0x[0-9a-fA-F]+)")
                if faddr_str then
                    local faddr = uint64(faddr_str)
                    local fp = rq(faddr + 0x20)
                    if fp then
                        local fp_h, fp_l = 0, 0
                        if type(fp) == "table" and fp.h then fp_h = fp.h; fp_l = fp.l
                        else fp_l = to_num(fp) end
                        local eb_h2, eb_l2 = 0, 0
                        if type(eboot) == "table" and eboot.h then eb_h2 = eboot.h; eb_l2 = eboot.l end
                        if fp_h == eb_h2 and fp_l >= eb_l2 and fp_l < eb_l2 + 0x200000 then
                            print(string.format("    C func: eboot+0x%X", fp_l - eb_l2))
                        else
                            print("    C func: " .. q(fp))
                        end
                    end
                end
            end
        end
    end
end

-- =================================================================
-- SECTION B: Read fn_addr, arg_addr heap layout
-- =================================================================
print("")
print("=== [B] HEAP DISPATCH LAYOUT ===")

local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")

if fn_str then
    local fn_addr_slot = uint64(fn_str)
    print("[B] fn_addr slot: " .. q(fn_addr_slot))
    local fn_val = rq(fn_addr_slot)
    if fn_val then
        print("[B] fn_addr value: " .. q(fn_val))
    end

    -- The arg slots should be at known offsets from fn_addr
    -- From 47a: fn_addr=+0x40, syscall_no=+0x50, rdi=+0x60, rsi=+0x70...
    -- So base = fn_addr_slot - 0x40
    -- Actually from 47a the addresses were: fn_addr=0x3109b4040, syscall_no=0x3109b4050
    -- So they're at +0x00, +0x10, +0x20, +0x30 offsets from fn_addr
    print("[B] scanning dispatch struct:")
    for off = -0x20, 0x80, 8 do
        local v = rq(fn_addr_slot + off)
        if v then
            print(string.format("  fn_addr%+d: %s", off, q(v)))
        end
    end
end

if rop_str then
    local rop_base = uint64(rop_str)
    print("")
    print("[B] ropchain base: " .. q(rop_base))
    -- Dump first 64 bytes of ropchain
    for off = 0, 0x38, 8 do
        local v = rq(rop_base + off)
        if v then
            print(string.format("  rop+0x%02X: %s", off, q(v)))
        end
    end
end

-- =================================================================
-- SECTION C: Scan eboot for call rax (FF D0) and jmp rax (FF E0)
-- Use dword scanning for speed
-- =================================================================
print("")
print("=== [C] CALL/JMP RAX SCAN ===")

local text_size = rd(info + 0x110) or 0
if text_size == 0 or text_size > 0x200000 then text_size = 0x200000 end

local call_rax_count = 0
local jmp_rax_count = 0
local call_rax_first = nil
local jmp_rax_first = nil

for off = 0, text_size - 4, 2 do
    local w = rd(eboot + off)
    if w then
        local lo16 = w % 0x10000
        if lo16 == 0xD0FF then  -- FF D0 = call rax
            call_rax_count = call_rax_count + 1
            if call_rax_count <= 10 then
                local after = rb(eboot + off + 2) or 0
                local tag = ""
                if after == 0xC3 then tag = " *** call rax;ret ***" end
                print(string.format("  call rax at eboot+0x%X (after=0x%02X)%s", off, after, tag))
            end
            if not call_rax_first then call_rax_first = off end
        end
        if lo16 == 0xE0FF then  -- FF E0 = jmp rax
            jmp_rax_count = jmp_rax_count + 1
            if jmp_rax_count <= 10 then
                print(string.format("  jmp rax at eboot+0x%X", off))
            end
            if not jmp_rax_first then jmp_rax_first = off end
        end
    end

    if off % 0x80000 == 0 and off > 0 then
        print("[*] scan: 0x" .. string.format("%X", off) .. "...")
    end
end

print(string.format("[C] call rax: %d, jmp rax: %d", call_rax_count, jmp_rax_count))

-- =================================================================
-- SECTION D: Dump 32 bytes around each syscall instruction
-- =================================================================
print("")
print("=== [D] SYSCALL CONTEXT DUMP ===")

local syscall_offsets = {0x93CBD, 0x1017E2, 0x12403C, 0x1577A6}

for _, sc_off in ipairs(syscall_offsets) do
    -- Verify it's really 0F 05
    local b0 = rb(eboot + sc_off)
    local b1 = rb(eboot + sc_off + 1)
    if b0 == 0x0F and b1 == 0x05 then
        print(string.format("  SYSCALL at eboot+0x%X:", sc_off))

        -- Dump 32 bytes before
        local before = ""
        for j = -32, -1 do
            local b = rb(eboot + sc_off + j)
            if b then before = before .. string.format("%02X ", b)
            else before = before .. "?? " end
        end
        print("    -32: " .. before:sub(1, 48))
        print("    -16: " .. before:sub(49))

        -- Dump 32 bytes after
        local after = ""
        for j = 0, 31 do
            local b = rb(eboot + sc_off + j)
            if b then after = after .. string.format("%02X ", b)
            else after = after .. "?? " end
        end
        print("     +0: " .. after:sub(1, 48))
        print("    +16: " .. after:sub(49))

        -- Look for ret within 20 bytes after syscall
        for k = 2, 20 do
            if rb(eboot + sc_off + k) == 0xC3 then
                print(string.format("    → ret at +%d bytes from syscall", k))
                break
            end
        end
        print("")
    end
end

-- =================================================================
-- SECTION E: Scan for int 0x80 (CD 80)
-- =================================================================
print("")
print("=== [E] INT 0x80 SCAN ===")

local int80_count = 0
for off = 0, text_size - 4, 2 do
    local w = rd(eboot + off)
    if w then
        if (w % 0x10000) == 0x80CD then
            int80_count = int80_count + 1
            if int80_count <= 5 then
                -- Check for ret nearby
                local has_ret = false
                for k = 2, 10 do
                    if rb(eboot + off + k) == 0xC3 then has_ret = true; break end
                end
                print(string.format("  int 0x80 at eboot+0x%X ret_nearby=%s", off, tostring(has_ret)))
            end
        end
    end
end
print("[E] int 0x80 count: " .. int80_count)

print("")
print("=== PROBE 80t COMPLETE ===")
