-- CRASH_CLASS: LOW
-- PROBE 143k: Use native_invoke for direct function calls +
-- read kernel_offset.lua for 14.10 entries +
-- try sceKernelGetModuleInfoFromAddr for kernel info

print("=== PROBE 143k: NATIVE_INVOKE + KOFFSETS ===")

--------------------------------------------------------------------
-- [A] Test native_invoke cmd=2 (fcall) for syscalls
--------------------------------------------------------------------
print("--- [A] native_invoke syscalls ---")

if native_invoke then
    -- native_invoke(cmd=2, fn_addr, rax, rdi, rsi, rdx, rcx, r8, r9)
    -- For syscalls: fn_addr=syscall_address, rax=syscall_num

    -- getpid(20)
    local ok, rv = pcall(function()
        return native_invoke(2, syscall.syscall_address, 20)
    end)
    if ok then print("[A] getpid=" .. tostring(rv)) else print("[A] getpid FAIL: " .. tostring(rv)) end

    -- getuid(24)
    ok, rv = pcall(function()
        return native_invoke(2, syscall.syscall_address, 24)
    end)
    if ok then print("[A] getuid=" .. tostring(rv)) else print("[A] getuid FAIL: " .. tostring(rv)) end

    -- Try sys 670 (one-shot) via native_invoke
    ok, rv = pcall(function()
        return native_invoke(2, syscall.syscall_address, 670)
    end)
    if ok then print("[A] sys670=" .. tostring(rv)) else print("[A] sys670 FAIL: " .. tostring(rv)) end

else
    print("[A] native_invoke not available")
end

--------------------------------------------------------------------
-- [B] Test native_invoke cmd=0 (read_buffer) on eboot
--------------------------------------------------------------------
print("")
print("--- [B] native read_buffer ---")

if native_invoke then
    -- cmd=0: read_buffer(addr, size) -> returns string
    local ok, data = pcall(function()
        return native_invoke(0, eboot_base, 16)
    end)
    if ok and type(data) == "string" then
        local bytes = ""
        for i = 1, math.min(#data, 16) do
            bytes = bytes .. string.format("%02X ", string.byte(data, i))
        end
        print("[B] eboot header: " .. bytes)
    else
        print("[B] read_buffer FAIL: " .. tostring(data))
    end

    -- Read libkernel header
    ok, data = pcall(function()
        return native_invoke(0, libkernel_base, 16)
    end)
    if ok and type(data) == "string" then
        local bytes = ""
        for i = 1, math.min(#data, 16) do
            bytes = bytes .. string.format("%02X ", string.byte(data, i))
        end
        print("[B] libkernel header: " .. bytes)
    else
        print("[B] libkernel read FAIL: " .. tostring(data))
    end
end

--------------------------------------------------------------------
-- [C] Call sceKernelGetModuleInfoFromAddr for kernel module detection
--------------------------------------------------------------------
print("")
print("--- [C] sceKernelGetModuleInfoFromAddr ---")

if native_invoke and libc_addrofs and libc_addrofs.sceKernelGetModuleInfoFromAddr then
    -- First resolve the actual function address (GOT entry)
    local fn_ptr = memory.read_qword(libc_addrofs.sceKernelGetModuleInfoFromAddr)
    print("[C] sceKernelGetModuleInfoFromAddr ptr=" .. hex(fn_ptr))

    -- Call it with libkernel_base to see the output format
    local mod_info = memory.alloc(0x300)
    memory.write_dword(mod_info, 0x300)  -- size field

    local ok, ret = pcall(function()
        return native_invoke(2, fn_ptr, 0, libkernel_base, 1, mod_info)
    end)
    if ok then
        print("[C] ret=" .. tostring(ret))
        -- Dump first 0x200 bytes of mod_info
        for off = 0, 0x1F0, 8 do
            local q = memory.read_qword(mod_info + off)
            if q then
                local h, l = 0, 0
                if type(q) == "table" and q.h then h = q.h; l = q.l
                else l = tonumber(q) or 0 end
                if h ~= 0 or l ~= 0 then
                    print("[C] +" .. string.format("%03X", off) .. "=" .. hex(q))
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        print("[C] *** KERNEL PTR at +" .. string.format("%03X", off) .. " ***")
                    end
                end
            end
        end
    else
        print("[C] FAIL: " .. tostring(ret))
    end

    -- Try with eboot_base
    memory.write_dword(mod_info, 0x300)
    ok, ret = pcall(function()
        return native_invoke(2, fn_ptr, 0, eboot_base, 1, mod_info)
    end)
    print("[C] eboot ret=" .. tostring(ret))
end

--------------------------------------------------------------------
-- [D] Read kernel_offset.lua for 14.10 entry
--------------------------------------------------------------------
print("")
print("--- [D] kernel_offset.lua ---")

-- Read file directly via Lua io (since we're in the loader environment)
local ok_read, text = pcall(function()
    local f = io.open("/savedata0/kernel_offset.lua", "r")
    if not f then return nil end
    local content = f:read("*all")
    f:close()
    return content
end)

if ok_read and text then
    print("[D] kernel_offset.lua: " .. #text .. " bytes")
    -- Search for version strings near 14.10 (or 7.xx, 8.xx, 9.xx, 10.xx etc)
    -- Print lines containing version numbers or "14"
    local pos = 1
    local line_no = 0
    local in_block = false
    while pos <= #text do
        local nl = text:find("\n", pos) or #text + 1
        local line = text:sub(pos, nl - 1)
        line_no = line_no + 1

        -- Print lines containing version numbers we care about
        if line:find("14%.") or line:find("13%.") or line:find("12%.") or
           line:find("11%.") or line:find("10%.") or line:find("9%.") or
           line:find("8%.") or line:find("7%.") or line:find("6%.") then
            in_block = true
        end

        if in_block then
            print(line)
            if line:find("^%s*},%s*$") or line:find("^%s*}$") then
                in_block = false
                print("")
            end
        end

        pos = nl + 1
    end
else
    print("[D] io.open failed, trying via syscall")
    -- Fallback: read via make_syscall
    local function make_syscall2(num)
        local t = {}
        for k, v in pairs(syscall.pipe) do t[k] = v end
        t.syscall_no = num
        setmetatable(t, getmetatable(syscall.pipe))
        return t
    end

    local sc_o = make_syscall2(5)
    local path = "/savedata0/kernel_offset.lua"
    local pbuf = memory.alloc(256)
    for ci = 0, #path - 1 do
        local off = ci - (ci % 4)
        local cur = memory.read_dword(pbuf + off) or 0
        local shift = (ci % 4) * 8
        cur = cur - (math.floor(cur / 2^shift) % 256) * 2^shift
            + string.byte(path, ci + 1) * 2^shift
        memory.write_dword(pbuf + off, cur)
    end
    memory.write_byte(pbuf + #path, 0)

    local ok2, fd = pcall(function() return sc_o(uint64(pbuf), uint64(0)) end)
    if ok2 then
        local sc_r = make_syscall2(3)
        local sc_c = make_syscall2(6)
        local sc_ls = make_syscall2(478)

        local fdv = type(fd) == "table" and fd:tonumber() or (tonumber(fd) or 0)
        print("[D] fd=" .. fdv)

        -- Seek to byte 4000
        pcall(function() return sc_ls(uint64(fdv), uint64(4000), uint64(0)) end)

        local rbuf = memory.alloc(0x4000)
        local total = 0
        local ttext = ""

        for chunk = 0, 3 do
            memory.write_dword(rbuf, 0)
            local ok3, rv3 = pcall(function() return sc_r(uint64(fdv), uint64(rbuf), uint64(0x4000)) end)
            if not ok3 then break end
            local rl = type(rv3) == "table" and rv3:tonumber() or (tonumber(rv3) or 0)
            if rl <= 0 or rl > 0x4000 then break end
            total = total + rl
            ttext = ttext .. memory.read_buffer(rbuf, rl)
            if rl < 0x4000 then break end
        end

        print("[D] read " .. total .. " bytes from offset 4000")

        -- Find lines with version numbers
        local pos = 1
        local in_block = false
        while pos <= #ttext do
            local nl = ttext:find("\n", pos) or #ttext + 1
            local line = ttext:sub(pos, nl - 1)

            if line:find("14%.") or line:find("13%.") or line:find("12%.") or
               line:find("11%.") or line:find("10%.") or line:find("9%.") or
               line:find("8%.") or line:find("7%.") or line:find("6%.") then
                in_block = true
            end

            if in_block then
                print(line)
                if line:find("^%s*},%s*$") or line:find("^%s*}$") then
                    in_block = false
                    print("")
                end
            end

            pos = nl + 1
        end

        pcall(function() return sc_c(uint64(fdv)) end)
    end
end

--------------------------------------------------------------------
-- [E] List files in /savedata0/
--------------------------------------------------------------------
print("")
print("--- [E] /savedata0/ listing ---")

local ok_ls, dir_text = pcall(function()
    -- Use Lua os.execute or io.popen
    -- Actually these probably don't work, let's just try opening known files
    local files = {
        "globals.lua", "offsets.lua", "misc.lua", "bit32.lua",
        "hash.lua", "uint64.lua", "struct.lua", "lua.lua",
        "memory.lua", "ropchain.lua", "syscall.lua", "signal.lua",
        "native.lua", "thread.lua", "kernel_offset.lua", "kernel.lua",
        "gpu.lua"
    }

    for _, name in ipairs(files) do
        local path = "/savedata0/" .. name
        local f = io.open(path, "r")
        if f then
            local size = 0
            local content = f:read("*all")
            if content then size = #content end
            f:close()
            print("[E] " .. name .. " = " .. size .. " bytes")
        end
    end
end)

if not ok_ls then
    print("[E] listing FAIL: " .. tostring(dir_text))
end

print("")
print("=== DONE ===")
