-- CRASH_CLASS: LOW
-- PROBE 796b: what is syscall 626 cmd 5 actually reading
--
-- 796a: 626(5, *, idx 0..3, out, 0) -> ret 0, eight zero bytes at out. idx >= 4 -> -1.
-- arg4 NULL -> -1, arg5 != 0 -> -1, arg2 ignored.
--
-- Tests, in order of information value:
--   [A] all six commands x idx 0..3 with arg2=0 (some other case may need idx != 0)
--   [B] read idx 0..3, spin, read again: if the value grows the source is a running
--       performance counter, if it stays zero the source is a fixed register.
--   [C] arg2 sensitivity 0..4 at the answering command
--   [D] arg4 unmapped -> EFAULT, proving it is a copyout of the value

print("=== PROBE 796b: syscall 626 cmd 5 source ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function addrnum(v)
    if type(v) == "table" then
        if v.h and v.l then return u64(v.h, v.l) end
        return uint64(to_num(v))
    end
    return uint64(to_num(v))
end
local function q(buf)
    local h, l = get_hi_lo(safe_rq(buf))
    return string.format("%08X%08X", h, l)
end
local function fill(buf)
    for i = 0, 0x1C, 4 do safe_wd(buf + i, 0xCDCD0000 + i) end
end

local sc626 = make_syscall(626)
local out = memory.alloc(0x40)

print("[A] cmd x idx matrix, arg2=0 arg4=out arg5=0")
for cmd = 1, 6 do
    local line = string.format("  cmd=%-2d", cmd)
    for idx = 0, 3 do
        fill(out)
        local ok, rv = pcall(function()
            return sc626(uint64(cmd), uint64(0), uint64(idx), addrnum(out), uint64(0))
        end)
        local r = ok and to_num(rv) or -999
        line = line .. string.format("  idx%d:r=%d/%s", idx, r, (r == 0) and q(out) or "--------")
    end
    print(line)
end

print("")
print("[B] time behaviour at cmd 5 (values read ~60 ms apart)")
local vals = {}
for idx = 0, 3 do
    fill(out)
    pcall(function() return sc626(uint64(5), uint64(0), uint64(idx), addrnum(out), uint64(0)) end)
    vals[idx] = q(out)
end
local t0 = os.clock()
local acc = 0
while os.clock() - t0 < 0.06 do acc = acc + 1 end
local vals2 = {}
for idx = 0, 3 do
    fill(out)
    pcall(function() return sc626(uint64(5), uint64(0), uint64(idx), addrnum(out), uint64(0)) end)
    vals2[idx] = q(out)
end
for idx = 0, 3 do
    print(string.format("  idx=%d first=%s second=%s spins=%d", idx, vals[idx], vals2[idx], acc))
end

print("")
print("[C] arg2 sensitivity at cmd 5, idx 0 and 1")
for _, a2 in ipairs({ 0, 1, 2, 3, 4, 0x1000 }) do
    local line = string.format("  arg2=%-6d", a2)
    for idx = 0, 1 do
        fill(out)
        local ok, rv = pcall(function()
            return sc626(uint64(5), uint64(a2), uint64(idx), addrnum(out), uint64(0))
        end)
        line = line .. string.format("  idx%d:r=%d/%s", idx, ok and to_num(rv) or -999, q(out))
    end
    print(line)
end

print("")
print("[D] arg4 pointer checks at cmd 5 idx 0")
local probes = {
    { 0xDEAD0000, "unmapped" },
    { 0xFFFF0000, "unmapped-high" },
}
for _, p in ipairs(probes) do
    local ok, rv = pcall(function()
        return sc626(uint64(5), uint64(0), uint64(0), uint64(p[1]), uint64(0))
    end)
    print(string.format("  arg4=%08X (%s) ret=%d", p[1], p[2], ok and to_num(rv) or -999))
end

print("")
print(string.format("[E] alive q=%s", q(out)))
