-- CRASH_CLASS: RISKY
-- PROBE 567a: syscall 601 (mdbg_service) command sweep, correct shape
--
-- Context: 601's body reads the command from [uap+0], arg1 from [uap+8], arg2
-- from [uap+0x10], and dispatches through a 0x28-entry jump table. Earlier
-- sweeps passed the command *as* arg1, so every case either hit a NULL arg or
-- faulted a copyin. This sweep passes a mapped 0x40 page as arg1 and NULL as
-- arg2, and prints the return value and any page change per command.

print("=== PROBE 567a: MDBG COMMAND SWEEP ===")

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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function rd(addr)
    local ok, v = pcall(function() return to_num(memory.read_dword(addr)) end)
    if ok then return v end
    return -1
end
local function u64(hi, lo)
    return uint64(string.format("0x%08X%08X", hi, lo))
end

local PAGE = 0x1000
local p = to_num(memory.alloc(PAGE))
for off = 0, PAGE - 4, 4 do safe_wd(p + off, 0) end
print(string.format("[A] page=0x%08X size=%d", p, PAGE))

local sc = make_syscall(601)
for cmd = 0, 0x13 do
    for off = 0, 0x3C, 4 do safe_wd(p + off, 0) end
    print(string.format("[%02X] calling", cmd))
    local ok, ret = pcall(function()
        return sc(u64(0, cmd), u64(0, p), u64(0, 0), u64(0, 0), u64(0, 0), u64(0, 0))
    end)
    local rv = ok and tostring(ret) or "PCALL-FAIL"
    local s = ""
    for off = 0, 0x3C, 4 do
        local v = rd(p + off)
        if v ~= 0 then s = s .. string.format(" %02X=%08X", off, v) end
    end
    if s == "" then s = " (all zero)" end
    print(string.format("  ret=%s page:%s", rv, s))
end

print("=== 567a DONE ===")
