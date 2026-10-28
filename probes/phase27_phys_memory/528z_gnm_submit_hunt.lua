-- CRASH_CLASS: LOW
-- PROBE 528z: Find GNM submit and GPU DMA wrappers
--
-- The GPU submit path on PS5 goes through libSceGnmDriver or libSceVideoOut.
-- We need to find:
-- 1. What modules are loaded that relate to GPU/graphics
-- 2. The submit wrapper's GOT entry in these modules
-- 3. Whether we can call submit to inject our own PM4 packets
--
-- Also: enumerate sys 649 member types on GPU-related modules
-- to find function pointers we can call.

print("=== PROBE 528z: GNM SUBMIT HUNT ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- ============================================================
-- [A] Enumerate all loaded modules, find GPU-related ones
-- ============================================================
print("[A] Module enumeration")

local sc_593 = mk(593)
local sc_649 = mk(649)

local gpu_modules = {}
local all_modules = {}

for h = 0, 0x200 do
    local ib = memory.alloc(0x200)
    wd(N(ib), 0x160)
    local ok_i, rv_i = pcall(function() return sc_593(uint64(h), ib) end)
    if ok_i and N(rv_i) == 0 then
        local name = ""
        for i = 0, 39 do
            local b = rd(N(ib) + 8 + i)
            if b then
                local c = b % 256
                if c == 0 then break end
                if c >= 32 and c < 127 then name = name .. string.char(c) end
            end
        end

        local text_lo = rd(N(ib) + 0x108) or 0
        local text_hi = rd(N(ib) + 0x10C) or 0
        if text_lo < 0 then text_lo = text_lo + 0x100000000 end
        if text_hi < 0 then text_hi = text_hi + 0x100000000 end
        local text_size_lo = rd(N(ib) + 0x110) or 0
        if text_size_lo < 0 then text_size_lo = text_size_lo + 0x100000000 end

        local data_lo = rd(N(ib) + 0x120) or 0
        local data_hi = rd(N(ib) + 0x124) or 0
        if data_lo < 0 then data_lo = data_lo + 0x100000000 end
        if data_hi < 0 then data_hi = data_hi + 0x100000000 end
        local data_size_lo = rd(N(ib) + 0x128) or 0
        if data_size_lo < 0 then data_size_lo = data_size_lo + 0x100000000 end

        table.insert(all_modules, {
            handle = h,
            name = name,
            text_hi = text_hi, text_lo = text_lo,
            text_size = text_size_lo,
            data_hi = data_hi, data_lo = data_lo,
            data_size = data_size_lo
        })

        -- GPU-related module names
        local lname = name:lower()
        if lname:find("gnm") or lname:find("gpu") or lname:find("video") or
           lname:find("graph") or lname:find("render") or lname:find("compute") or
           lname:find("display") or lname:find("gc") or lname:find("dce") then
            table.insert(gpu_modules, all_modules[#all_modules])
            print(string.format("  *** h=%d %s text=0x%X%08X sz=0x%X data=0x%X%08X sz=0x%X",
                h, name, text_hi, text_lo, text_size_lo, data_hi, data_lo, data_size_lo))
        end
    end
end

print(string.format("  total modules=%d gpu-related=%d", #all_modules, #gpu_modules))
print("")

-- Print ALL module names for reference
print("[A2] All modules:")
for i, m in ipairs(all_modules) do
    print(string.format("  h=%d %s (text=0x%X%08X+0x%X)",
        m.handle, m.name, m.text_hi, m.text_lo, m.text_size))
end

-- ============================================================
-- [B] For GPU modules: query sys 649 member types 1-8
-- to find function pointers (submit, map, etc.)
-- ============================================================
print("")
print("[B] sys 649 on GPU-related modules")

for _, m in ipairs(gpu_modules) do
    print(string.format("  module: %s (handle=%d)", m.name, m.handle))
    local outbuf = memory.alloc(0x100)
    for mtype = 1, 8 do
        wq(N(outbuf), uint64(0))
        local ok_649, rv_649 = pcall(function()
            return sc_649(uint64(m.handle), uint64(mtype), uint64(outbuf))
        end)
        if ok_649 then
            local ret = N(rv_649)
            local val = rq(N(outbuf))
            if ret == 0 and val then
                local vh, vl = get_hi_lo(val)
                if vh < 0 then vh = vh + 0x100000000 end
                if vl < 0 then vl = vl + 0x100000000 end
                if vl ~= 0 or vh ~= 0 then
                    print(string.format("    type=%d: 0x%X%08X", mtype, vh, vl))
                end
            end
        end
    end
end

-- ============================================================
-- [C] Search module .data sections for GOT entries pointing
-- to known submit-related patterns
-- GNM submit typically writes to a specific syscall
-- ============================================================
print("")
print("[C] GOT/PLT scan in GPU modules for syscall patterns")

-- For each GPU module, read first 1024 qwords of .data section
-- looking for function pointers into libkernel (syscall wrappers)
for _, m in ipairs(gpu_modules) do
    if m.data_size > 0 then
        local base = uint64(string.format("0x%X%08X", m.data_hi, m.data_lo))
        local scan_size = math.min(m.data_size, 0x2000)  -- 8 KB
        print(string.format("  %s .data scan (%d bytes)", m.name, scan_size))

        local ptrs = {}
        for off = 0, scan_size - 8, 8 do
            local v = rq(N(base) + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh < 0 then vh = vh + 0x100000000 end
                if vl < 0 then vl = vl + 0x100000000 end
                -- Look for pointers into other modules' text ranges
                for _, tm in ipairs(all_modules) do
                    if vh == tm.text_hi then
                        local diff = vl - tm.text_lo
                        if diff >= 0 and diff < tm.text_size then
                            table.insert(ptrs, {off, tm.name, diff, vh, vl})
                            if #ptrs <= 30 then
                                print(string.format("    [+0x%04X] -> %s+0x%X",
                                    off, tm.name, diff))
                            end
                        end
                    end
                end
            end
        end
        if #ptrs > 30 then
            print(string.format("    ... %d total GOT entries", #ptrs))
        end
    end
end

-- ============================================================
-- [D] Search eboot for string references to "submit" or "gnm"
-- ============================================================
print("")
print("[D] eboot string scan for GPU keywords")

-- Find eboot
local eboot = nil
for _, m in ipairs(all_modules) do
    if m.name == "eboot.bin" or m.handle == 0 then
        eboot = m
        break
    end
end

if eboot then
    local base = uint64(string.format("0x%X%08X", eboot.data_hi, eboot.data_lo))
    local scan_size = math.min(eboot.data_size, 0x10000)  -- 64 KB
    print(string.format("  eboot .data at 0x%X%08X sz=0x%X", eboot.data_hi, eboot.data_lo, eboot.data_size))

    -- Scan for ASCII strings containing "submit", "gnm", "gpu", "dma"
    local found = {}
    local chunk_size = 256
    for off = 0, scan_size - chunk_size, chunk_size do
        local str = ""
        for i = 0, chunk_size - 1 do
            local b = rd(N(base) + off + i)
            if b then
                local c = b % 256
                if c >= 32 and c < 127 then
                    str = str .. string.char(c)
                else
                    -- Check accumulated string
                    local ls = str:lower()
                    if #str > 4 and (ls:find("submit") or ls:find("gnm") or
                        ls:find("dma") or ls:find("command") or ls:find("gpu")) then
                        table.insert(found, {off + i - #str, str})
                    end
                    str = ""
                end
            end
        end
    end

    print(string.format("  GPU-related strings: %d", #found))
    for i, f in ipairs(found) do
        if i > 30 then break end
        local display = f[2]
        if #display > 80 then display = display:sub(1, 80) .. "..." end
        print(string.format("    [+0x%X] %s", f[1], display))
    end
end

print("")
print("=== 528z DONE ===")
