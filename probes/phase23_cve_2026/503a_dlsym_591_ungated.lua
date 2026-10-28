-- CRASH_CLASS: LOW
-- PROBE 503a: syscall 591 dynlib_dlsym — ungated kernel symbol resolution
--
-- 13.60 offline decode (OFFLINE_HANDLER_DECODE_2026-10-23): handler 0x34ae90,
-- narg 3: 591(handle: u32, name: char*, out_addr: u64*).
-- NO authid gate, NO bit-62 gate. The only precondition is a valid handle
-- (from the 593 handle space) and a valid NID/symbol name string.
-- Prior probes returned -1 because they passed zeros; with real args from
-- the 593 module list this should resolve symbols.
--
-- If 14.10 kept this handler ungated, it is a kernel-side dlsym for every
-- loaded module — we can resolve any exported function address.

print("=== PROBE 503a: dynlib_dlsym(591) ungated ===")
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

local sc20  = make_syscall(20)   -- getpid
local sc591 = make_syscall(591)  -- dynlib_dlsym
local sc593 = make_syscall(593)  -- dynlib_get_info
local sc594 = make_syscall(594)  -- dynlib_load_prx (might work)

local pid = to_num(sc20())
print("pid: " .. pid)

------------------------------------------------------------------ [A] enumerate module handles via 593
-- 593 returns info for handles 0..N. We know 39 modules exist.
-- Collect valid handles and their names.

print("")
print("[A] Enumerating module handles via 593...")

local handles = {}
local info = memory.alloc(0x200)

for h = 0, 50 do
    -- zero the buffer
    for i = 0, 0x1FC, 4 do safe_wd(info + i, 0) end
    safe_wd(info, 0x160)  -- size field

    local ok, ret = pcall(function()
        return sc593(uint64(h), info)
    end)

    if ok then
        local rv = to_num(ret)
        if rv == 0 then
            -- read module name from +0x08 (path string, up to 256 chars)
            local name = ""
            for i = 0, 63 do
                local b = safe_rd(info + 0x08 + i)
                if not b or b == 0 then break end
                -- read byte by byte from dword
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
            table.insert(handles, h)
            if #handles <= 10 then
                print(string.format("  handle=%d name=%.60s", h, name))
            end
        end
    end
end
print("  total valid handles: " .. #handles)

if #handles == 0 then
    print("FATAL: no module handles found")
    print("=== PROBE 503a COMPLETE ===")
    return
end

------------------------------------------------------------------ [B] write NID strings to memory
-- Common NIDs/symbols to try resolving. The PS5 uses NID encoding but
-- also may accept plain names. We try both styles.

print("")
print("[B] Preparing symbol name strings...")

local function make_str(s)
    local buf = memory.alloc(#s + 16)
    for i = 1, #s do
        pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

-- plain C names that libkernel/libc would export
local sym_names = {
    "sceKernelGetModuleInfo",
    "sceKernelDlsym",
    "sceKernelLoadStartModule",
    "sceKernelGetProcParam",
    "sceKernelSendNotificationRequest",
    "sceKernelDebugOutText",
    "sceKernelGetCurrentCpu",
    "sceKernelUsleep",
    "sceKernelOpen",
    "sceKernelClose",
    "sceKernelRead",
    "sceKernelWrite",
    "sceKernelMmap",
    "sceKernelMunmap",
    "sceKernelJitCreateSharedMemory",
    "getpid",
    "socket",
    "close",
    "mmap",
    "printf",
}

local sym_bufs = {}
for _, name in ipairs(sym_names) do
    sym_bufs[name] = make_str(name)
end

------------------------------------------------------------------ [C] try 591 with each handle + symbol name
print("")
print("[C] Testing 591 dynlib_dlsym...")

local out_buf = memory.alloc(8)
local found_any = false

-- test a few handles with all symbol names
local test_handles = {}
for i = 1, math.min(#handles, 5) do
    table.insert(test_handles, handles[i])
end
-- also try special handles: -1 (RTLD_DEFAULT), -2 (RTLD_NEXT), 0
table.insert(test_handles, 0)
table.insert(test_handles, 0xFFFFFFFF)  -- -1 as u32
table.insert(test_handles, 0xFFFFFFFE)  -- -2 as u32

for _, h in ipairs(test_handles) do
    local h_label = h
    if h == 0xFFFFFFFF then h_label = "-1(RTLD_DEFAULT)" end
    if h == 0xFFFFFFFE then h_label = "-2(RTLD_NEXT)" end

    for _, name in ipairs(sym_names) do
        -- clear output
        safe_wq(out_buf, uint64(0xDEADBEEF))

        local ok, ret = pcall(function()
            return sc591(uint64(h), uint64(to_num(sym_bufs[name])),
                         uint64(to_num(out_buf)))
        end)

        if ok then
            local rv = to_num(ret)
            if rv == 0 then
                local addr = safe_rq(out_buf)
                print(string.format("  *** HIT *** handle=%s sym=%s addr=%s",
                    tostring(h_label), name, fmt_hex(addr)))
                found_any = true

                -- check if kernel pointer
                local ah, al = get_hi_lo(addr)
                if ah >= 0xFFFF8000 then
                    print("    ^^^ KERNEL POINTER ^^^")
                end
            end
            -- report first few -1s to show errno pattern
            if rv ~= 0 and h == handles[1] and
               (name == "sceKernelGetModuleInfo" or name == "getpid") then
                -- check what's in out_buf (unchanged = 0xDEADBEEF)
                local oval = safe_rq(out_buf)
                print(string.format("  handle=%s sym=%s ret=%d out=%s",
                    tostring(h_label), name, rv, fmt_hex(oval)))
            end
        else
            if h == handles[1] and name == "getpid" then
                print(string.format("  handle=%s sym=%s CRASHED", tostring(h_label), name))
            end
        end
    end
end

if not found_any then
    print("  no symbols resolved (all returned nonzero)")
end

------------------------------------------------------------------ [D] try 594 dynlib_load_prx
print("")
print("[D] Testing 594 dynlib_load_prx (module load)...")

-- 594(path, flags, &handle, 0)
-- try loading a module we know exists
local prx_paths = {
    "/app0/sce_module/libc.prx",
    "/app0/sce_module/libSceNpManager.sprx",
    "/system/common/lib/libSceNet.sprx",
    "/system/common/lib/libkernel.sprx",
}

local handle_out = memory.alloc(8)
for _, path in ipairs(prx_paths) do
    safe_wq(handle_out, uint64(0))
    local pbuf = make_str(path)
    local ok, ret = pcall(function()
        return sc594(uint64(to_num(pbuf)), uint64(0),
                     uint64(to_num(handle_out)), uint64(0))
    end)
    if ok then
        local rv = to_num(ret)
        local hval = safe_rq(handle_out)
        print(string.format("  %s ret=%d handle=%s", path, rv, fmt_hex(hval)))
    else
        print(string.format("  %s CRASHED", path))
    end
end

------------------------------------------------------------------ [E] errno capture via fake TCB
-- The SCE error codes are returned via errno. On the main Lua thread,
-- errno is at fs:0 which we can read if we know the TCB.
print("")
print("[E] Checking errno accessibility...")
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
print("  fn_addr: " .. (fn_str or "nil"))

-- try reading errno location (the Lua thread already has a valid TCB)
-- errno is typically at TCB+0 or a known offset
-- On FreeBSD amd64, errno is at %fs:0 via __error() -> tls
-- We can't easily read fs:0 from Lua, but the return value itself
-- may carry the errno in some cases

------------------------------------------------------------------ verification
print("")
print("=== VERIFICATION ===")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " [OK]" or " [CHANGED!]"))

print("")
print("=== PROBE 503a COMPLETE ===")
