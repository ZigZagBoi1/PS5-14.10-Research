-- CRASH_CLASS: MODERATE
-- PROBE 797a: syscall 625 (the wrmsr sibling of 626)
--
-- 13.60 body 0x603c90, narg 4. arg1 selects one of 24 cases (1..0x17). Two visible cases:
--   0x603d73  arg2 in {1,2,3}, then an odd/even branch into an MSR access with count 0x36b
--   0x603d46  arg2|arg3 == 0 and arg4 == 0, then tail-call 0x8b33fe00
-- The block after the handler is four wrmsr over 0xc0010230..0xc0010238 with
-- `and eax, 0xffbf0000`, i.e. this family both reads and writes performance MSRs.
--
-- 626 answers only for cmd 5 (one counter, idx 0..3) and cmd 6 (eight counters, two pages).
-- 625 takes four arguments, so its cases are `625(cmd, a2, a3, a4)`. This probe walks all
-- 23 commands with a zeroed page at arg4 and reports which answer; then it repeats the
-- answering ones with arg2/arg3 variations and reads the page back.

print("=== PROBE 797a: syscall 625 command walk ===")
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
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function addrnum(v)
    if type(v) == "table" then return uint64(to_num(v)) end
    return uint64(to_num(v))
end

local sc625 = make_syscall(625)
local page = memory.alloc(0x400)
local function zero()
    for i = 0, 0x3FC, 4 do safe_wd(page + i, 0) end
end
local function head()
    local s = ""
    for i = 0, 3 do s = s .. string.format("%08X", safe_rd(page + i*4) or 0) end
    return s
end
local function call(cmd, a2, a3, a4)
    local ok, rv = pcall(function()
        return sc625(uint64(cmd), uint64(a2), uint64(a3), addrnum(a4))
    end)
    return ok and to_num(rv) or -999
end

print("[A] cmd 1..0x17 with arg2=0 arg3=0 arg4=page")
local ok_cmds = {}
for cmd = 1, 0x17 do
    zero()
    local r = call(cmd, 0, 0, page)
    if r == 0 then ok_cmds[#ok_cmds + 1] = cmd end
    print(string.format("  cmd=%2d ret=%d %s", cmd, r, head()))
end

print("")
print("[B] commanding set: " .. tostring(#ok_cmds))
for _, cmd in ipairs(ok_cmds) do
    for _, a2 in ipairs({ 0, 1, 2, 3, 4 }) do
        zero()
        local r = call(cmd, a2, 0, page)
        print(string.format("  cmd=%d a2=%d ret=%d %s", cmd, a2, r, head()))
    end
    for _, a3 in ipairs({ 0, 1, 2, 3, 4, 5, 6, 7 }) do
        zero()
        local r = call(cmd, 0, a3, page)
        print(string.format("  cmd=%d a3=%d ret=%d %s", cmd, a3, r, head()))
    end
end

print("")
print("[C] arg4 controls at the first answering cmd")
if #ok_cmds > 0 then
    local cmd = ok_cmds[1]
    print("  arg4=0 ret=" .. call(cmd, 0, 0, 0))
    print("  arg4=unmapped ret=" .. call(cmd, 0, 0, 0xDEAD0000))
end

print("")
print("[D] alive")
