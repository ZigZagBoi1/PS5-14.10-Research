-- CRASH_CLASS: LOW
-- PROBE 505a: syscall 591 with NID-encoded symbol names
--
-- 503a confirmed 591 is alive (ret=-1, no crash) but rejects plain ASCII.
-- PS4/PS5 use NID encoding: SHA1(name + suffix) -> first 8 bytes -> base64.
-- The suffix varies by library. Common suffix for libkernel is empty or
-- known from public PS4 research.
--
-- Strategy: try multiple NID formats and known PS4/PS5 NIDs.
-- Also try: handle from 594 (loaded module), raw ordinal numbers,
-- and the NID with/without the '#' prefix some loaders use.

print("=== PROBE 505a: dlsym(591) NID resolution ===")
print("")

------------------------------------------------------------------ helpers
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
local function fmt_hex(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local function make_str(s)
    local buf = memory.alloc(#s + 16)
    for i = 1, #s do
        pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local sc20  = make_syscall(20)
local sc591 = make_syscall(591)
local sc593 = make_syscall(593)
local sc594 = make_syscall(594)

local pid = to_num(sc20())
print("pid: " .. pid)

------------------------------------------------------------------ [A] get handles
print("")
print("[A] Collecting module handles...")

local handles = {}
local info = memory.alloc(0x200)

for h = 0, 50 do
    for i = 0, 0x1FC, 4 do safe_wd(info + i, 0) end
    safe_wd(info, 0x160)
    local ok, ret = pcall(function() return sc593(uint64(h), info) end)
    if ok and to_num(ret) == 0 then
        local name = ""
        for i = 0, 63 do
            local b = safe_rd(info + 0x08 + i * 4)
            if not b or b == 0 then break end
            local c = b % 256
            if c == 0 then break end
            name = name .. string.char(c)
            c = math.floor(b / 256) % 256
            if c == 0 then break end
            name = name .. string.char(c)
            c = math.floor(b / 65536) % 256
            if c == 0 then break end
            name = name .. string.char(c)
            c = math.floor(b / 16777216) % 256
            if c == 0 then break end
            name = name .. string.char(c)
        end
        table.insert(handles, {id = h, name = name})
        print(string.format("  handle=%d name=%.50s", h, name))
    end
end
print("  total: " .. #handles)

if #handles == 0 then
    print("FATAL: no handles")
    return
end

------------------------------------------------------------------ [B] known PS4/PS5 NIDs
-- These NIDs are from public PS4 homebrew/research databases.
-- Format: NID string (11 chars base64) = function name
-- The kernel dlsym may accept: "NID", "#NID", or plain name
print("")
print("[B] Testing 591 with known NIDs...")

local nid_table = {
    -- libkernel NIDs (from public PS4 wiki/databases)
    {"2wxrr2X3PX8", "sceKernelGetModuleInfoByName"},
    {"LwG8g3niqwA", "sceKernelDlsym"},
    {"WB66d2Whkig", "sceKernelLoadStartModule"},
    {"959qrazGqiU", "sceKernelGetProcParam"},
    {"HoLVWNanBBc", "sceKernelSendNotificationRequest"},
    {"wzvqT4UqKX8", "sceKernelDebugOutText"},
    {"lLMT9hM1nvY", "sceKernelGetCurrentCpu"},
    {"QcteRwbsnV0", "sceKernelUsleep"},
    {"wuCroIGjt2g", "sceKernelOpen"},
    {"bY-PO6JhzhQ", "sceKernelClose"},
    {"Cg4srZ6TKbU", "sceKernelRead"},
    {"4wSze92BhLI", "sceKernelWrite"},
    {"BPE9s9vQQXo", "sceKernelMmap"},
    {"UqDGjXA5yUM", "sceKernelMunmap"},
    {"MywrWJot0do", "sceKernelJitCreateSharedMemory"},
    {"HF4IcC0EQWI", "sceKernelJitCreateAliasOfSharedMemory"},
    {"gQm0Iy8R3W4", "sceKernelJitMapSharedMemory"},
    {"2SKEx6bSq-Y", "getpid"},
    {"6xVpy0Lj6QU", "sceKernelGetModuleInfo"},
    {"n5S3K9FYp0g", "sceKernelGetModuleInfoFromAddr"},
}

local out_buf = memory.alloc(8)
local found_any = false

for _, entry in ipairs(nid_table) do
    local nid, func_name = entry[1], entry[2]

    -- try each handle with the NID
    for _, hinfo in ipairs(handles) do
        local h = hinfo.id

        -- format 1: raw NID
        safe_wq(out_buf, uint64(0xDEADBEEF))
        local nid_buf = make_str(nid)
        local ok, ret = pcall(function()
            return sc591(uint64(h), uint64(to_num(nid_buf)),
                         uint64(to_num(out_buf)))
        end)

        if ok and to_num(ret) == 0 then
            local addr = safe_rq(out_buf)
            print(string.format("  *** HIT *** h=%d NID=%s (%s) addr=%s",
                h, nid, func_name, fmt_hex(addr)))
            found_any = true
            local ah, al = get_hi_lo(addr)
            if ah >= 0xFFFF8000 and ah < 0xFFFFFFFF then
                print("    ^^^ KERNEL POINTER ^^^")
            end
        end

        -- format 2: #NID (some loaders use this prefix)
        safe_wq(out_buf, uint64(0xDEADBEEF))
        local hash_nid_buf = make_str("#" .. nid)
        local ok2, ret2 = pcall(function()
            return sc591(uint64(h), uint64(to_num(hash_nid_buf)),
                         uint64(to_num(out_buf)))
        end)

        if ok2 and to_num(ret2) == 0 then
            local addr = safe_rq(out_buf)
            print(string.format("  *** HIT *** h=%d #%s (%s) addr=%s",
                h, nid, func_name, fmt_hex(addr)))
            found_any = true
            local ah, al = get_hi_lo(addr)
            if ah >= 0xFFFF8000 and ah < 0xFFFFFFFF then
                print("    ^^^ KERNEL POINTER ^^^")
            end
        end

        -- only try first 3 handles per NID to save time
        if h >= handles[3].id then break end
    end
end

------------------------------------------------------------------ [C] try ordinal numbers
print("")
print("[C] Testing 591 with ordinal numbers (0-20)...")

for ord = 0, 20 do
    for _, hinfo in ipairs(handles) do
        local h = hinfo.id
        safe_wq(out_buf, uint64(0xDEADBEEF))

        local ok, ret = pcall(function()
            return sc591(uint64(h), uint64(ord), uint64(to_num(out_buf)))
        end)

        if ok and to_num(ret) == 0 then
            local addr = safe_rq(out_buf)
            print(string.format("  *** HIT *** h=%d ord=%d addr=%s",
                h, ord, fmt_hex(addr)))
            found_any = true
        end

        if h >= handles[3].id then break end
    end
end

------------------------------------------------------------------ [D] try module:name format
print("")
print("[D] Testing 591 with module:name format...")

local combined_names = {
    "libkernel#sceKernelGetModuleInfo",
    "libkernel#getpid",
    "libSceLibcInternal#malloc",
    "libSceLibcInternal#printf",
    "libc#getpid",
    "libc#malloc",
}

for _, cname in ipairs(combined_names) do
    for _, hinfo in ipairs(handles) do
        local h = hinfo.id
        safe_wq(out_buf, uint64(0xDEADBEEF))
        local name_buf = make_str(cname)

        local ok, ret = pcall(function()
            return sc591(uint64(h), uint64(to_num(name_buf)),
                         uint64(to_num(out_buf)))
        end)

        if ok and to_num(ret) == 0 then
            local addr = safe_rq(out_buf)
            print(string.format("  *** HIT *** h=%d name=%s addr=%s",
                h, cname, fmt_hex(addr)))
            found_any = true
        end

        if h >= handles[3].id then break end
    end
end

------------------------------------------------------------------ [E] try empty/special strings
print("")
print("[E] Testing 591 with special inputs...")

local special = {"", "\x00", "*", "?", "\xff"}
for _, s in ipairs(special) do
    safe_wq(out_buf, uint64(0xDEADBEEF))
    local sbuf = make_str(s)
    local ok, ret = pcall(function()
        return sc591(uint64(handles[1].id), uint64(to_num(sbuf)),
                     uint64(to_num(out_buf)))
    end)
    if ok then
        local rv = to_num(ret)
        local oval = safe_rq(out_buf)
        if rv == 0 then
            print(string.format("  *** HIT *** special='%s' addr=%s",
                s, fmt_hex(oval)))
            found_any = true
        end
    end
end

------------------------------------------------------------------ [F] try 594 to load libkernel, then dlsym on it
print("")
print("[F] Load libkernel via 594, then dlsym...")

local paths_to_try = {
    "/system/common/lib/libkernel.sprx",
    "/system/common/lib/libkernel_sys.sprx",
    "/system/common/lib/libkernel_web.sprx",
    "libkernel.sprx",
    "libkernel",
}

local handle_out = memory.alloc(8)
for _, path in ipairs(paths_to_try) do
    safe_wq(handle_out, uint64(0))
    local pbuf = make_str(path)
    local ok, ret = pcall(function()
        return sc594(uint64(to_num(pbuf)), uint64(0),
                     uint64(to_num(handle_out)), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local hval = safe_rq(handle_out)
        print(string.format("  594(%s) ret=%d handle=%s", path, rv, fmt_hex(hval)))
        if rv == 0 then
            local loaded_h = to_num(hval)
            -- now try dlsym on this handle
            local test_nids = {"2SKEx6bSq-Y", "6xVpy0Lj6QU", "LwG8g3niqwA"}
            for _, nid in ipairs(test_nids) do
                safe_wq(out_buf, uint64(0xDEADBEEF))
                local nb = make_str(nid)
                local ok2, ret2 = pcall(function()
                    return sc591(uint64(loaded_h), uint64(to_num(nb)),
                                 uint64(to_num(out_buf)))
                end)
                if ok2 and to_num(ret2) == 0 then
                    local addr = safe_rq(out_buf)
                    print(string.format("    *** HIT *** dlsym(%d, %s) = %s",
                        loaded_h, nid, fmt_hex(addr)))
                    found_any = true
                end
            end
        end
    else
        print(string.format("  594(%s) CRASHED", path))
    end
end

------------------------------------------------------------------ [G] error code capture
-- The make_syscall wrapper returns the raw value. On failure, FreeBSD
-- returns -1 with errno set. The actual SCE error might be in the return
-- value itself on PS5 (positive = SCE error code).
print("")
print("[G] Detailed return value analysis for 591...")

-- call with known-good handle + ASCII name, capture full return
local test_names = {"getpid", "malloc", "sceKernelOpen"}
for _, name in ipairs(test_names) do
    local nbuf = make_str(name)
    safe_wq(out_buf, uint64(0xDEADBEEF))
    local ok, ret = pcall(function()
        return sc591(uint64(handles[1].id), uint64(to_num(nbuf)),
                     uint64(to_num(out_buf)))
    end)
    if ok then
        local rh, rl = get_hi_lo(ret)
        print(string.format("  591(h=%d, '%s') raw_ret=0x%X%08X (%d)",
            handles[1].id, name, rh, rl, to_num(ret)))
    end
end

-- also try with NULL name pointer
safe_wq(out_buf, uint64(0xDEADBEEF))
local ok_null, ret_null = pcall(function()
    return sc591(uint64(handles[1].id), uint64(0), uint64(to_num(out_buf)))
end)
if ok_null then
    print(string.format("  591(h=%d, NULL) ret=%d", handles[1].id, to_num(ret_null)))
else
    print(string.format("  591(h=%d, NULL) CRASHED", handles[1].id))
end

-- try with invalid handle
safe_wq(out_buf, uint64(0xDEADBEEF))
local nbuf2 = make_str("getpid")
local ok_bad, ret_bad = pcall(function()
    return sc591(uint64(9999), uint64(to_num(nbuf2)), uint64(to_num(out_buf)))
end)
if ok_bad then
    print(string.format("  591(h=9999, 'getpid') ret=%d", to_num(ret_bad)))
end

------------------------------------------------------------------ summary
print("")
print("=== SUMMARY ===")
if found_any then
    print("*** SYMBOLS RESOLVED — SEE HITS ABOVE ***")
else
    print("No symbols resolved with any format tested.")
    print("Next: need SHA1-based NID computation in Lua,")
    print("or a known NID database specific to PS5 14.10")
end

print("")
print("=== VERIFICATION ===")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " [OK]" or " [CHANGED!]"))
print("")
print("=== PROBE 505a COMPLETE ===")
