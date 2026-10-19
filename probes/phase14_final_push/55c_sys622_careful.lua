-- CRASH_CLASS: MODERATE
-- PROBE 55c: sys 622 device control — careful one-at-a-time scan
--
-- Context: 55b showed cmd 0x200 returned ret=0 with buf[0]=FFFFFFFF,
-- then the process crashed (game crash) before reaching cmd 0x201.
-- sys 622 is a 24KB handler with 300+ commands, many unauthenticated.
-- RE shows bitmap auth: 0xF8FFF000000D5 selects commands needing auth.
-- Commands with bit NOT set skip auth entirely.
--
-- Plan: test each command carefully with a getpid heartbeat between them.
-- If we find commands that return interesting data or modify state,
-- those are potential exploit primitives.

print("=== PROBE 55c: sys 622 CAREFUL DEVICE CONTROL SCAN ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X_%08X", h, l)
end

local sc622 = make_syscall(622)
local sc20 = make_syscall(20)

-- Heartbeat check
local function alive()
    local ok, v = pcall(function() return sc20() end)
    return ok
end

local pid_ok, pid_val = pcall(function() return sc20() end)
print("PID: " .. to_num(pid_val))

-- [A] Re-test cmd 0x200 with larger output buffer and dump full result
print("")
print("[A] cmd 0x200 detailed dump")
do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc622(uint64(0x200), uint64(0), uint64(buf), uint64(buf), uint64(0x100))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        for off = 0, 0x3C, 4 do
            local v = safe_rd(buf + off)
            if v and v ~= 0 then
                print(string.format("    +0x%02X: 0x%08X", off, v))
            end
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- [B] Scan 0x200 range one at a time
print("")
print("[B] cmd 0x200-0x27F scan")
for cmd = 0x200, 0x27F do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(0), uint64(buf), uint64(buf), uint64(0x100))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        local b0 = safe_rd(buf)
        local b4 = safe_rd(buf + 4)
        local b8 = safe_rd(buf + 8)
        if l ~= 0xFFFFFFFF or (b0 and b0 ~= 0) then
            print(string.format("  0x%X: ret=%s buf=%08X %08X %08X",
                cmd, hexval(ret), b0 or 0, b4 or 0, b8 or 0))
        end
    else
        print(string.format("  0x%X: CRASHED", cmd))
        if not alive() then print("  PROCESS DEAD after cmd " .. string.format("0x%X", cmd)); return end
    end
end
print("  0x200-0x27F done")

-- [C] Scan 0x300 range (device context ops per RE)
print("")
print("[C] cmd 0x300-0x320 scan")
for cmd = 0x300, 0x320 do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(0), uint64(buf), uint64(buf), uint64(0x100))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        local b0 = safe_rd(buf)
        local b4 = safe_rd(buf + 4)
        local b8 = safe_rd(buf + 8)
        if l ~= 0xFFFFFFFF or (b0 and b0 ~= 0) then
            print(string.format("  0x%X: ret=%s buf=%08X %08X %08X",
                cmd, hexval(ret), b0 or 0, b4 or 0, b8 or 0))
        end
    else
        print(string.format("  0x%X: CRASHED", cmd))
        if not alive() then print("  PROCESS DEAD after cmd " .. string.format("0x%X", cmd)); return end
    end
end
print("  0x300-0x320 done")

-- [D] Scan 0x400 range (property/VRAM ops per RE)
print("")
print("[D] cmd 0x400-0x493 scan")
for cmd = 0x400, 0x493 do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(0), uint64(buf), uint64(buf), uint64(0x100))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        local b0 = safe_rd(buf)
        local b4 = safe_rd(buf + 4)
        local b8 = safe_rd(buf + 8)
        if l ~= 0xFFFFFFFF or (b0 and b0 ~= 0) then
            print(string.format("  0x%X: ret=%s buf=%08X %08X %08X",
                cmd, hexval(ret), b0 or 0, b4 or 0, b8 or 0))
        end
    else
        print(string.format("  0x%X: CRASHED", cmd))
        if not alive() then print("  PROCESS DEAD after cmd " .. string.format("0x%X", cmd)); return end
    end
end
print("  0x400-0x493 done")

-- [E] Scan the 0x100 range — bitmap auth, 15 commands skip auth
-- Bitmap 0xF8FFF000000D5: bits 0,2,4,6,7 set → cmds 0x100,0x102,0x104,0x106,0x107 need auth
-- The rest (0x101,0x103,0x105,0x108-0x133) skip auth
print("")
print("[E] cmd 0x100-0x133 scan (bitmap-gated)")
for cmd = 0x100, 0x133 do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(0), uint64(buf), uint64(buf), uint64(0x100))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        local b0 = safe_rd(buf)
        local b4 = safe_rd(buf + 4)
        local b8 = safe_rd(buf + 8)
        if l ~= 0xFFFFFFFF or (b0 and b0 ~= 0) then
            print(string.format("  0x%X: ret=%s buf=%08X %08X %08X",
                cmd, hexval(ret), b0 or 0, b4 or 0, b8 or 0))
        end
    else
        print(string.format("  0x%X: CRASHED", cmd))
        if not alive() then print("  PROCESS DEAD after cmd " .. string.format("0x%X", cmd)); return end
    end
end
print("  0x100-0x133 done")

-- [F] Any commands returning ret=0 from above, dump full buffer
print("")
print("[F] Detailed dump of cmd 0x200 (known ret=0)")
do
    local buf = memory.alloc(0x200)
    for i = 0, 0x1FC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc622(uint64(0x200), uint64(0), uint64(buf), uint64(buf), uint64(0x200))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        local any_kptr = false
        for off = 0, 0x78, 4 do
            local v = safe_rd(buf + off)
            if v then
                local tag = ""
                if v >= 0xFFFF8000 then tag = " <<< KERNEL?" end
                if v ~= 0 then
                    print(string.format("    +0x%02X: 0x%08X%s", off, v, tag))
                end
            end
        end
        -- Check qwords for kernel pointers
        for off = 0, 0x78, 8 do
            local lo = safe_rd(buf + off)
            local hi = safe_rd(buf + off + 4)
            if hi and hi >= 0xFFFF8000 and lo and lo ~= 0 then
                print(string.format("    +0x%02X QWORD: 0x%08X_%08X  <<< KERNEL PTR!", off, hi, lo))
                any_kptr = true
            end
        end
        if any_kptr then
            print("  >>> KERNEL POINTER FOUND IN CMD 0x200 OUTPUT!")
        end
    end
end

-- [G] Test with arg1 != 0 (device handle/context ID)
print("")
print("[G] cmd 0x200 with different arg1 values")
for _, arg1 in ipairs({1, 2, 3, 4, 0xFF, 0x100}) do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc622(uint64(0x200), uint64(arg1), uint64(buf), uint64(buf), uint64(0x100))
    end)
    if ok then
        local b0 = safe_rd(buf)
        print(string.format("  arg1=%d: ret=%s buf[0]=%08X", arg1, hexval(ret), b0 or 0))
    else
        print(string.format("  arg1=%d: CRASHED", arg1))
    end
end

-- [H] Test 0x500-0x520 range (may exist beyond documented ranges)
print("")
print("[H] cmd 0x500-0x520 scan (undocumented)")
for cmd = 0x500, 0x520 do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(0), uint64(buf), uint64(buf), uint64(0x100))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        local b0 = safe_rd(buf)
        if l ~= 0xFFFFFFFF or (b0 and b0 ~= 0) then
            print(string.format("  0x%X: ret=%s buf=%08X", cmd, hexval(ret), b0 or 0))
        end
    else
        print(string.format("  0x%X: CRASHED", cmd))
        if not alive() then print("  PROCESS DEAD after cmd " .. string.format("0x%X", cmd)); return end
    end
end
print("  0x500-0x520 done")

print("")
print("=== PROBE 55c COMPLETE ===")
