-- CRASH_CLASS: LOW
-- PROBE 143j: Dump loader globals and read offsets.lua + rest of kernel_offset.lua
-- 143i revealed the loader architecture. Now we need:
-- 1. Available globals (gadgets, eboot_addrofs, native_invoke)
-- 2. offsets.lua for game-specific gadget addresses
-- 3. kernel_offset.lua versions 6.00+ (especially 14.10)

print("=== PROBE 143j: GLOBALS + OFFSETS ===")

--------------------------------------------------------------------
-- [A] Dump critical globals
--------------------------------------------------------------------
print("--- [A] globals ---")

-- Check what's available
print("[A] PLATFORM=" .. tostring(PLATFORM))
print("[A] FW_VERSION=" .. tostring(FW_VERSION))
print("[A] game_name=" .. tostring(game_name))

if eboot_base then print("[A] eboot_base=" .. hex(eboot_base)) end
if libc_base then print("[A] libc_base=" .. hex(libc_base)) end
if libkernel_base then print("[A] libkernel_base=" .. hex(libkernel_base)) end

if kernel_offset then
    print("[A] kernel_offset table exists!")
    for k, v in pairs(kernel_offset) do
        if type(v) ~= "function" then
            print("[A] ko." .. tostring(k) .. "=" .. tostring(v))
        end
    end
else
    print("[A] kernel_offset=nil")
end

if kernel and kernel.addr then
    print("[A] kernel.addr:")
    for k, v in pairs(kernel.addr) do
        print("[A] k.addr." .. tostring(k) .. "=" .. tostring(v))
    end
end

print("[A] kernel.rw_initialized=" .. tostring(kernel and kernel.rw_initialized))

if syscall.syscall_address then
    print("[A] syscall_address=" .. hex(syscall.syscall_address))
end

if native_invoke then
    print("[A] native_invoke EXISTS (type=" .. type(native_invoke) .. ")")
end

if native_cmd_handler then
    print("[A] native_cmd_handler EXISTS")
end

-- Dump gadgets table
if gadgets then
    print("[A] gadgets table:")
    for k, v in pairs(gadgets) do
        if type(v) == "table" then
            for kk, vv in pairs(v) do
                if type(vv) ~= "function" then
                    print("[A] g." .. tostring(k) .. "." .. tostring(kk) .. "=" .. tostring(vv))
                end
            end
        elseif type(v) ~= "function" then
            print("[A] g." .. tostring(k) .. "=" .. tostring(v))
        end
    end
else
    print("[A] gadgets=nil")
end

-- Dump eboot_addrofs keys
if eboot_addrofs then
    print("[A] eboot_addrofs:")
    local count = 0
    for k, v in pairs(eboot_addrofs) do
        if count < 30 then
            print("[A] ea." .. tostring(k) .. "=" .. tostring(v))
            count = count + 1
        end
    end
    if count >= 30 then print("[A] ... (more entries)") end
else
    print("[A] eboot_addrofs=nil")
end

-- Dump libc_addrofs keys
if libc_addrofs then
    print("[A] libc_addrofs:")
    local count = 0
    for k, v in pairs(libc_addrofs) do
        if count < 20 then
            print("[A] la." .. tostring(k) .. "=" .. tostring(v))
            count = count + 1
        end
    end
else
    print("[A] libc_addrofs=nil")
end

--------------------------------------------------------------------
-- [B] Test fcall directly
--------------------------------------------------------------------
print("")
print("--- [B] fcall test ---")

if type(fcall) == "function" then
    print("[B] fcall is available!")

    -- Try calling getpid through fcall with syscall_address
    if syscall.syscall_address then
        local ok, rv = pcall(function()
            return fcall(syscall.syscall_address, 20)()
        end)
        if ok then
            print("[B] fcall getpid=" .. tostring(rv))
        else
            print("[B] fcall getpid FAIL: " .. tostring(rv))
        end
    end

    -- Try calling getuid(24) via fcall
    if syscall.syscall_address then
        local ok, rv = pcall(function()
            return fcall(syscall.syscall_address, 24)()
        end)
        if ok then
            print("[B] fcall getuid=" .. tostring(rv))
        else
            print("[B] fcall getuid FAIL: " .. tostring(rv))
        end
    end
else
    print("[B] fcall not available (type=" .. type(fcall) .. ")")
end

--------------------------------------------------------------------
-- [C] Test native_invoke for memory.read_buffer
-- (this is the fast path for reading arbitrary memory)
--------------------------------------------------------------------
print("")
print("--- [C] native_invoke ---")

if native_invoke then
    -- native_invoke(cmd, ...) where cmd is:
    -- 0 = read_buffer(addr, size)
    -- 1 = write_buffer(dest, data)
    -- 2 = fcall(fn, rax, rdi, rsi, rdx, rcx, r8, r9)

    -- Try reading eboot header
    if eboot_base then
        local ok, rv = pcall(function()
            return native_invoke(0, eboot_base, 16)
        end)
        if ok then
            print("[C] eboot header: " .. tostring(rv))
            if type(rv) == "string" then
                local bytes = ""
                for i = 1, math.min(#rv, 16) do
                    bytes = bytes .. string.format("%02X ", string.byte(rv, i))
                end
                print("[C] bytes: " .. bytes)
            end
        else
            print("[C] read eboot FAIL: " .. tostring(rv))
        end
    end
else
    print("[C] native_invoke not available")
end

--------------------------------------------------------------------
-- [D] Read offsets.lua
--------------------------------------------------------------------
print("")
print("--- [D] offsets.lua ---")

local function read_file(path, max_bytes)
    max_bytes = max_bytes or 32768
    local function to_num2(v)
        if type(v) == "table" and v.tonumber then return v:tonumber() end
        return tonumber(v) or 0
    end
    local function make_syscall2(num)
        local t = {}
        for k, v in pairs(syscall.pipe) do t[k] = v end
        t.syscall_no = num
        setmetatable(t, getmetatable(syscall.pipe))
        return t
    end
    local function safe_rd2(addr)
        local ok, val = pcall(function() return memory.read_dword(addr) end)
        if ok then return to_num2(val) end
        return nil
    end
    local function wd2(addr, val) memory.write_dword(addr, val) end

    local path_buf = memory.alloc(256)
    for ci = 0, #path - 1 do
        local off = ci
        local addr = path_buf + off - (off % 4)
        local cur = safe_rd2(addr) or 0
        local shift = (off % 4) * 8
        cur = cur - (math.floor(cur / 2^shift) % 256) * 2^shift
            + string.byte(path, ci + 1) * 2^shift
        wd2(addr, cur)
    end
    local toff = #path
    local taddr = path_buf + toff - (toff % 4)
    local tcur = safe_rd2(taddr) or 0
    local tshift = (toff % 4) * 8
    tcur = tcur - (math.floor(tcur / 2^tshift) % 256) * 2^tshift
    wd2(taddr, tcur)

    local sc_o = make_syscall2(5)
    local ok, fd_r = pcall(function() return sc_o(uint64(path_buf), uint64(0)) end)
    if not ok then return nil, "open failed" end
    local fh, fl = 0, to_num2(fd_r)
    if type(fd_r) == "table" and fd_r.h then fh = fd_r.h; fl = fd_r.l end
    if fl >= 256 or fh ~= 0 then return nil, "open ret=" .. fl end

    local rbuf = memory.alloc(0x1000)
    local sc_r = make_syscall2(3)
    local sc_c = make_syscall2(6)
    local total = 0
    local text = ""

    for chunk = 0, 31 do
        for off = 0, 0xFFF, 4 do wd2(rbuf + off, 0) end
        local ok2, rv2 = pcall(function() return sc_r(uint64(fl), uint64(rbuf), uint64(4096)) end)
        if not ok2 then break end
        local rh2, rl2 = 0, to_num2(rv2)
        if type(rv2) == "table" and rv2.h then rh2 = rv2.h; rl2 = rv2.l end
        if rl2 == 0 or rl2 > 4096 then break end
        total = total + rl2
        for ci = 0, math.min(rl2 - 1, 4095) do
            local word_off = ci - (ci % 4)
            local w = safe_rd2(rbuf + word_off)
            if w then
                local shift = (ci % 4) * 8
                local ch = math.floor(w / (2^shift)) % 256
                if ch >= 32 and ch < 127 then
                    text = text .. string.char(ch)
                elseif ch == 10 then text = text .. "\n"
                elseif ch == 9 then text = text .. "\t"
                elseif ch == 0 then break
                else text = text .. "."
                end
            end
        end
        if rl2 < 4096 or total >= max_bytes then break end
    end
    pcall(function() return sc_c(uint64(fl)) end)
    return text, total
end

local text, total = read_file("/savedata0/offsets.lua", 12000)
if text then
    print("[D] offsets.lua: " .. total .. " bytes")
    local pos = 1
    while pos <= #text and pos <= 10000 do
        local nl = text:find("\n", pos) or math.min(pos + 200, #text + 1)
        print(text:sub(pos, nl - 1))
        pos = nl + 1
    end
else
    print("[D] offsets.lua: " .. tostring(total))
end

--------------------------------------------------------------------
-- [E] Read kernel_offset.lua from byte 4000+ (newer versions)
--------------------------------------------------------------------
print("")
print("--- [E] kernel_offset.lua remainder ---")

-- Open and seek past what we already read
local ok_e, text_e = pcall(function()
    local t, n = read_file("/savedata0/kernel_offset.lua", 20000)
    return t
end)

if ok_e and text_e then
    -- Print from byte 4000 onward
    if #text_e > 4000 then
        local pos = 4001
        local printed = 0
        while pos <= #text_e and printed < 12000 do
            local nl = text_e:find("\n", pos) or math.min(pos + 200, #text_e + 1)
            print(text_e:sub(pos, nl - 1))
            pos = nl + 1
            printed = printed + (nl - pos + 1)
        end
    end
end

print("")
print("=== DONE ===")
