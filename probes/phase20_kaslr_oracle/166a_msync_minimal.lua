-- CRASH_CLASS: MODERATE
-- PROBE 166a: Minimal msync isolation — is syscall 226 blocked entirely?

print("=== PROBE 166a: MSYNC MINIMAL ===")

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
local function fmt(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        return string.format("0x%X%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end

local sc226 = make_syscall(226)  -- msync
local sc477 = make_syscall(477)  -- mmap
local sc73  = make_syscall(73)   -- munmap
local sc20  = make_syscall(20)   -- getpid

print("PID: " .. tostring(to_num(sc20())))

-- T1: msync(NULL, 0, 0) — invalid args, should return EINVAL
print("")
print("--- T1: msync(NULL, 0, 0) ---")
print("  calling...")
local ok1, rv1 = pcall(function()
    return sc226(uint64(0), uint64(0), uint64(0))
end)
print("  " .. (ok1 and "ret=" .. fmt(rv1) or "PCALL-FAIL"))

-- T2: msync(NULL, PAGE, 0) — invalid addr
print("")
print("--- T2: msync(NULL, 0x4000, 0) ---")
print("  calling...")
local ok2, rv2 = pcall(function()
    return sc226(uint64(0), uint64(0x4000), uint64(0))
end)
print("  " .. (ok2 and "ret=" .. fmt(rv2) or "PCALL-FAIL"))

-- T3: mmap PRIVATE ANON, NO page touch, then msync
print("")
print("--- T3: mmap(PRIV|ANON) + msync (no write) ---")
local ok3, addr3 = pcall(function()
    return sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok3 then
    print("  mmap: " .. fmt(addr3))
    print("  calling msync(MS_SYNC=0)...")
    local ok3b, rv3 = pcall(function()
        return sc226(uint64(addr3), uint64(0x4000), uint64(0))
    end)
    print("  " .. (ok3b and "ret=" .. fmt(rv3) or "PCALL-FAIL"))
    pcall(function() sc73(uint64(addr3), uint64(0x4000)) end)
else
    print("  mmap FAIL")
end

-- T4: mmap SHARED ANON (0x1001), no write, then msync
print("")
print("--- T4: mmap(SHARED|ANON) + msync (no write) ---")
local ok4, addr4 = pcall(function()
    return sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1001), uint64(0xFFFFFFFF), uint64(0))
end)
if ok4 then
    print("  mmap: " .. fmt(addr4))
    print("  calling msync(MS_SYNC=0)...")
    local ok4b, rv4 = pcall(function()
        return sc226(uint64(addr4), uint64(0x4000), uint64(0))
    end)
    print("  " .. (ok4b and "ret=" .. fmt(rv4) or "PCALL-FAIL"))
    pcall(function() sc73(uint64(addr4), uint64(0x4000)) end)
else
    print("  mmap FAIL: " .. tostring(addr4))
end

-- T5: mmap PRIV ANON, write page, then msync
print("")
print("--- T5: mmap(PRIV|ANON) + WRITE + msync ---")
local ok5, addr5 = pcall(function()
    return sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok5 then
    print("  mmap: " .. fmt(addr5))
    pcall(function() memory.write_dword(addr5, 0x41414141) end)
    print("  wrote 0x41414141")
    print("  calling msync(MS_SYNC=0)...")
    local ok5b, rv5 = pcall(function()
        return sc226(uint64(addr5), uint64(0x4000), uint64(0))
    end)
    print("  " .. (ok5b and "ret=" .. fmt(rv5) or "PCALL-FAIL"))
    pcall(function() sc73(uint64(addr5), uint64(0x4000)) end)
else
    print("  mmap FAIL")
end

-- T6: mmap PRIV ANON, write, msync MS_INVALIDATE
print("")
print("--- T6: mmap(PRIV|ANON) + WRITE + msync(MS_INVALIDATE) ---")
local ok6, addr6 = pcall(function()
    return sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok6 then
    print("  mmap: " .. fmt(addr6))
    pcall(function() memory.write_dword(addr6, 0x42424242) end)
    print("  wrote 0x42424242")
    print("  calling msync(MS_INVALIDATE=2)...")
    local ok6b, rv6 = pcall(function()
        return sc226(uint64(addr6), uint64(0x4000), uint64(2))
    end)
    print("  " .. (ok6b and "ret=" .. fmt(rv6) or "PCALL-FAIL"))
    if ok6b then
        local ok6c, val6 = pcall(function() return memory.read_dword(addr6) end)
        print("  read after: " .. (ok6c and fmt(val6) or "FAULT"))
    end
    pcall(function() sc73(uint64(addr6), uint64(0x4000)) end)
else
    print("  mmap FAIL")
end

print("")
print("=== PROBE 166a COMPLETE ===")
