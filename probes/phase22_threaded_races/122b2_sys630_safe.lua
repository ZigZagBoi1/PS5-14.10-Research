-- CRASH_CLASS: MODERATE
-- PROBE 122b2: sys 630 safe mount enumeration test
--
-- 52a says 627-630 return PCALL-FAIL on six zeros.
-- 13.60 analysis says 630 is a 12KB mount handler with subcmds,
-- enumeration, cross-PID lookup, all without priv_check.
-- But we need the RIGHT arguments.
--
-- This probe tests 630 carefully inside pcall with various arg shapes.
-- No memory.write_byte — uses write_dword only.

print("=== PROBE 122b2: SYS 630 SAFE ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc630 = mk(630)

-- Helper: write a path string using dword writes
-- Pack bytes little-endian into dwords
local function put_path(base, s)
    local off = 0
    local dw = 0
    local shift = 0
    for i = 1, #s do
        local b = string.byte(s, i)
        dw = dw + b * (2 ^ shift)
        shift = shift + 8
        if shift == 32 then
            wd(base + off, dw)
            off = off + 4
            dw = 0
            shift = 0
        end
    end
    -- null terminator
    dw = dw + 0 * (2 ^ shift)
    shift = shift + 8
    if shift <= 32 then
        wd(base + off, dw)
    end
end

local buf = memory.alloc(0x2000)
local BUF = N(buf)
local outbuf = BUF + 0x800

-- Zero output area
for i = 0, 0x1FF, 4 do wd(outbuf + i, 0) end

-- [A] Six zeros — confirm PCALL-FAIL from 52a
print("[A] six zeros (baseline)")
local ok_a, rv_a = pcall(function()
    return sc630(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("  pcall=" .. tostring(ok_a) .. " rv=" .. (ok_a and tostring(N(rv_a)) or tostring(rv_a)))

local c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED after [A]!") return end
print("  alive=YES")

-- [B] Small sentinel values as first arg (1-10)
-- 629 used sentinel 1 to bypass path parsing. 630 may have similar sentinels.
print("")
print("[B] sentinel values")
for _, a0 in ipairs({1, 2, 3, 4, 5, 6, 7, 8, 9, 10}) do
    for i = 0, 0x3F, 4 do wd(outbuf + i, 0) end
    local ok_b, rv_b = pcall(function()
        return sc630(uint64(a0), uint64(outbuf), uint64(0x200), uint64(0))
    end)
    c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then
        print(string.format("  630(%d,...) -> KILLED PROCESS", a0))
        return
    end
    local w0 = rd(outbuf) or 0
    if w0 < 0 then w0 = w0 + 0x100000000 end
    local tag = ok_b and tostring(N(rv_b)) or "PFAIL"
    if w0 ~= 0 then
        tag = tag .. string.format(" [0]=%08X", w0)
    end
    print(string.format("  630(%d, outbuf, 0x200, 0) -> %s", a0, tag))
end

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [C] Path string: "/" in a buffer
print("")
print("[C] path strings")
local paths = {
    {0x0000002F, 1, "/"},          -- "/" + null
    {0x7665642F, 4, "/dev"},       -- "/dev" (LE: 2F 64 65 76)
    {0x00000000, 0, "(null ptr)"}, -- null pointer test
}

-- "/dev\0" = 2F 64 65 76 00
put_path(BUF, "/dev")
local dev_ptr = uint64(BUF)

-- "/" = 2F 00
put_path(BUF + 0x100, "/")
local root_ptr = uint64(BUF + 0x100)

-- "/app0" = 2F 61 70 70 30 00
put_path(BUF + 0x200, "/app0")
local app0_ptr = uint64(BUF + 0x200)

-- "/system" = 2F 73 79 73 74 65 6D 00
put_path(BUF + 0x300, "/system")
local sys_ptr = uint64(BUF + 0x300)

-- "/data" = 2F 64 61 74 61 00
put_path(BUF + 0x400, "/data")
local data_ptr = uint64(BUF + 0x400)

for _, entry in ipairs({
    {root_ptr, "/"},
    {dev_ptr, "/dev"},
    {app0_ptr, "/app0"},
    {sys_ptr, "/system"},
    {data_ptr, "/data"},
}) do
    local ptr, label = entry[1], entry[2]
    for i = 0, 0x3F, 4 do wd(outbuf + i, 0) end
    local ok_c, rv_c = pcall(function()
        return sc630(ptr, uint64(0), uint64(0), uint64(0))
    end)
    c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then
        print(string.format("  630(\"%s\") -> KILLED PROCESS", label))
        return
    end
    print(string.format("  630(\"%s\") -> %s", label, ok_c and tostring(N(rv_c)) or "PFAIL"))
end

-- [D] Try reading back what 630 returns in larger output buffers
-- Try: arg0=sentinel, arg1=outbuf (larger), arg2=outbuf_size
print("")
print("[D] large output buffer")
for i = 0, 0x3FF, 4 do wd(outbuf + i, 0) end
local ok_d, rv_d = pcall(function()
    return sc630(uint64(1), uint64(outbuf), uint64(0x400), uint64(0), uint64(0), uint64(0))
end)
if ok_d then
    local ret = N(rv_d)
    print("  630(1, outbuf, 0x400, 0,0,0) ret=" .. ret)
    -- Dump first 64 bytes of output
    local has_data = false
    for i = 0, 0x3C, 4 do
        local w = rd(outbuf + i)
        if w ~= nil and w ~= 0 then
            if w < 0 then w = w + 0x100000000 end
            has_data = true
            print(string.format("    +%02X: %08X", i, w))
        end
    end
    if not has_data then print("    (all zeros)") end
else
    print("  630(1, ...) PFAIL: " .. tostring(rv_d))
end

-- [E] Try calling 630 via the shape the 13.60 handler expects
-- The deep analysis says narg=1, so all args come from td_frame.
-- With narg=1, only arg0 is from the user; the handler reads more via copyin.
-- Maybe we need a struct pointer as arg0?
print("")
print("[E] struct pointer as arg0")
-- Build a struct at BUF+0x500: {int cmd, int pad, ptr data, size_t size}
local struct_base = BUF + 0x500
for i = 0, 0x3F, 4 do wd(struct_base + i, 0) end

-- Try each cmd value 0-10 via struct
for cmd = 0, 10 do
    wd(struct_base, cmd)  -- cmd field
    wd(struct_base + 4, 0)  -- pad
    wq(struct_base + 8, uint64(outbuf))  -- data ptr
    wq(struct_base + 16, uint64(0x200))  -- size

    for i = 0, 0x3F, 4 do wd(outbuf + i, 0) end
    local ok_e, rv_e = pcall(function()
        return sc630(uint64(struct_base), uint64(0), uint64(0), uint64(0))
    end)
    c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then
        print(string.format("  struct cmd=%d: KILLED", cmd))
        return
    end
    if ok_e then
        local ret = N(rv_e)
        local w0 = rd(outbuf) or 0
        if w0 < 0 then w0 = w0 + 0x100000000 end
        local tag = w0 ~= 0 and string.format(" [0]=%08X", w0) or ""
        print(string.format("  struct cmd=%d: ret=%d%s", cmd, ret, tag))
    else
        print(string.format("  struct cmd=%d: PFAIL", cmd))
    end
end

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

print("")
print(string.format("canary=%s", c == pid and "OK" or "FAIL"))
print("=== 122b2 COMPLETE ===")
