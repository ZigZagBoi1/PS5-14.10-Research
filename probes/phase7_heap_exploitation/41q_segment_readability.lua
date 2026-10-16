-- CRASH_CLASS: RISKY (may crash on XO text read)
-- PROBE 41q: test which module segments are readable
-- Theory: text segment may be execute-only (XO) on 14.10
-- If so, we can't scan for gadgets by reading code
-- Check: text, data, relro, each module
-- Also: dump all module info for offline gadget search

print("=== PROBE 41q: SEGMENT READABILITY ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function dump_qword(val)
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", val.h, val.l)
    end
    return string.format("%016X", to_num(val))
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local sc_dynlib_get_list = make_syscall(592)
local sc_dynlib_get_info = make_syscall(593)

--------------------------------------------------------------------
-- STEP 1: Get full module map with ALL segment info
--------------------------------------------------------------------
print("--- STEP 1: FULL MODULE MAP ---")

local handle_buf = memory.alloc(512)
local num_buf = memory.alloc(8)
pcall(function() sc_dynlib_get_list(handle_buf, uint64(128), num_buf) end)
local num_h = safe_rd(num_buf) or 0
print("modules: " .. num_h)

local info_buf = memory.alloc(0x200)

-- Collect module info
local modules = {}
for i = 0, math.min(num_h - 1, 38) do
    local h = safe_rd(handle_buf + i * 4)
    if h then
        for off = 0, 0x1F8, 4 do safe_wd(info_buf + off, 0) end
        safe_wd(info_buf, 0x160)
        local ok_gi = pcall(function() sc_dynlib_get_info(uint64(h), info_buf) end)
        if ok_gi then
            local name_bytes = {}
            for nb = 0, 39 do
                local c = safe_rb(info_buf + 0x08 + nb)
                if c and c > 0 and c < 128 then
                    name_bytes[#name_bytes + 1] = string.char(c)
                else break end
            end
            local name = table.concat(name_bytes)

            -- segment layout in info struct:
            -- +108: text_base(lo), +10C: text_base(hi)
            -- +110: text_size(lo), +114: text_size(hi) or next field
            -- +118: data_base(lo), +11C: data_base(hi)
            -- +120: data_size(lo)
            -- +128: relro_base(lo)? +12C: relro_base(hi)?
            -- +130: relro_size?
            -- +138: bss_base?
            -- +140: bss_size?
            local segs = {}
            for s = 0, 5 do
                local bl = safe_rd(info_buf + 0x108 + s * 0x10)
                local bh = safe_rd(info_buf + 0x10C + s * 0x10)
                local sl = safe_rd(info_buf + 0x110 + s * 0x10)
                if bl and bh and sl and (bl ~= 0 or bh ~= 0) then
                    segs[#segs + 1] = {
                        base_hex = string.format("0x%X%08X", bh, bl),
                        bh = bh, bl = bl,
                        size = sl,
                    }
                end
            end

            modules[#modules + 1] = {
                idx = i, handle = h, name = name, segs = segs
            }

            -- print compact info
            local parts = {}
            for si, seg in ipairs(segs) do
                parts[#parts + 1] = string.format("%s+0x%X", seg.base_hex, seg.size)
            end
            print(string.format("  [%2d] h=0x%04X %-32s %s",
                i, h, name, table.concat(parts, " | ")))
        end
    end
end
print("")

--------------------------------------------------------------------
-- STEP 2: Test readability of DATA segments
-- Data segments should be RW (readable). Start with these.
--------------------------------------------------------------------
print("--- STEP 2: DATA SEGMENT READABILITY ---")

for _, m in ipairs(modules) do
    if #m.segs >= 2 then
        -- seg[2] is typically data
        local dseg = m.segs[2]
        local addr = uint64(dseg.base_hex)
        local d = safe_rd(addr)
        local tag = d and string.format("%08X", d) or "FAULT"
        print(string.format("  %-24s data %s: %s", m.name, dseg.base_hex, tag))
    end
    if #m.name > 0 and m.name:find("kernel") then
        -- also try all segments for libkernel
        for si, seg in ipairs(m.segs) do
            local addr = uint64(seg.base_hex)
            local d = safe_rd(addr)
            print(string.format("    seg[%d] %s sz=0x%X: %s",
                si, seg.base_hex, seg.size,
                d and string.format("%08X", d) or "FAULT"))
        end
    end
end
print("")

--------------------------------------------------------------------
-- STEP 3: Try eboot (handle 0) — it's the main executable
-- Its text might be RX (not XO) since it's not a system lib
--------------------------------------------------------------------
print("--- STEP 3: EBOOT READABILITY ---")
do
    local eboot = nil
    for _, m in ipairs(modules) do
        if m.handle == 0 then eboot = m; break end
    end
    if eboot and #eboot.segs >= 1 then
        for si, seg in ipairs(eboot.segs) do
            local addr = uint64(seg.base_hex)
            local d = safe_rd(addr)
            print(string.format("  eboot seg[%d] %s sz=0x%X: %s",
                si, seg.base_hex, seg.size,
                d and string.format("%08X", d) or "FAULT"))
            -- if readable and this is text, scan a few bytes
            if d and si == 1 then
                print("  eboot text is READABLE! first 32 bytes:")
                local bytes = {}
                for b = 0, 31 do
                    local bv = safe_rb(addr + b)
                    if bv then
                        bytes[#bytes + 1] = string.format("%02X", bv)
                    else
                        bytes[#bytes + 1] = "??"
                        break
                    end
                end
                print("    " .. table.concat(bytes, " "))

                -- quick gadget scan in eboot text
                print("  quick gadget scan (first 0x4000 bytes):")
                local sr_count = 0
                local pop_rdi = 0
                local pop_rsi = 0
                local pop_rdx = 0
                local pop_rax = 0
                local jmp_rax_c = 0
                for off = 0, 0x3FFC, 4 do
                    local dw = safe_rd(addr + off)
                    if dw == nil then break end
                    local b0 = dw % 256
                    local b1 = math.floor(dw / 256) % 256
                    local b2 = math.floor(dw / 65536) % 256
                    local b3 = math.floor(dw / 16777216) % 256
                    if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then sr_count = sr_count + 1 end
                    if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 then sr_count = sr_count + 1 end
                    if b0 == 0x5F and b1 == 0xC3 then pop_rdi = pop_rdi + 1 end
                    if b1 == 0x5F and b2 == 0xC3 then pop_rdi = pop_rdi + 1 end
                    if b0 == 0x5E and b1 == 0xC3 then pop_rsi = pop_rsi + 1 end
                    if b1 == 0x5E and b2 == 0xC3 then pop_rsi = pop_rsi + 1 end
                    if b0 == 0x5A and b1 == 0xC3 then pop_rdx = pop_rdx + 1 end
                    if b1 == 0x5A and b2 == 0xC3 then pop_rdx = pop_rdx + 1 end
                    if b0 == 0x58 and b1 == 0xC3 then pop_rax = pop_rax + 1 end
                    if b1 == 0x58 and b2 == 0xC3 then pop_rax = pop_rax + 1 end
                    if b0 == 0xFF and b1 == 0xE0 then jmp_rax_c = jmp_rax_c + 1 end
                end
                print(string.format("    syscall;ret=%d pop_rdi=%d pop_rsi=%d pop_rdx=%d pop_rax=%d jmp_rax=%d",
                    sr_count, pop_rdi, pop_rsi, pop_rdx, pop_rax, jmp_rax_c))
            end
        end
    else
        print("  eboot not found")
    end
end
print("")

--------------------------------------------------------------------
-- STEP 4: Scan libkernel DATA segment for gadgets
-- Even in data, there may be embedded code (trampolines, plt stubs)
-- or pointer tables we can use
--------------------------------------------------------------------
print("--- STEP 4: LIBKERNEL DATA GADGETS ---")
do
    local libk = nil
    for _, m in ipairs(modules) do
        if m.name:find("kernel") then libk = m; break end
    end
    if libk and #libk.segs >= 2 then
        local dseg = libk.segs[2]
        local daddr = uint64(dseg.base_hex)
        local dtest = safe_rd(daddr)
        if dtest then
            print("  data readable, scanning " .. dseg.base_hex .. " sz=0x" .. string.format("%X", dseg.size))
            local sr_count = 0
            local interesting = {}
            local scan_max = math.min(dseg.size, 0x10000)
            for off = 0, scan_max - 4, 4 do
                local dw = safe_rd(daddr + off)
                if dw == nil then break end
                local b0 = dw % 256
                local b1 = math.floor(dw / 256) % 256
                local b2 = math.floor(dw / 65536) % 256
                local b3 = math.floor(dw / 16777216) % 256

                if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
                    sr_count = sr_count + 1
                    if #interesting < 8 then
                        interesting[#interesting + 1] = string.format("+0x%X: syscall;ret", off)
                    end
                end
                if b0 == 0x5F and b1 == 0xC3 then
                    if #interesting < 8 then
                        interesting[#interesting + 1] = string.format("+0x%X: pop rdi;ret", off)
                    end
                end
                if b0 == 0x58 and b1 == 0xC3 then
                    if #interesting < 8 then
                        interesting[#interesting + 1] = string.format("+0x%X: pop rax;ret", off)
                    end
                end
                if b0 == 0xFF and b1 == 0xE0 then
                    if #interesting < 8 then
                        interesting[#interesting + 1] = string.format("+0x%X: jmp rax", off)
                    end
                end
            end
            print("  syscall;ret in data: " .. sr_count)
            for _, s in ipairs(interesting) do
                print("    " .. s)
            end
        else
            print("  data segment also FAULT")
        end
    end
end
print("")

--------------------------------------------------------------------
-- STEP 5: Try other modules' text segments
-- Some user libraries might not have XO
--------------------------------------------------------------------
print("--- STEP 5: OTHER MODULE TEXT ---")
for _, m in ipairs(modules) do
    if #m.segs >= 1 and m.handle ~= 0 then
        local tseg = m.segs[1]
        local addr = uint64(tseg.base_hex)
        local d = safe_rd(addr)
        local tag = d and "READABLE" or "XO/FAULT"
        -- only print first 8 non-eboot modules
        if m.idx < 10 or d then
            print(string.format("  %-24s text %s: %s",
                m.name:sub(1, 24), tseg.base_hex, tag))
        end
        -- if readable, note it as a gadget source
        if d and m.idx > 0 then
            print("    *** READABLE TEXT - can scan for gadgets ***")
        end
    end
end
print("")

print("=== PROBE 41q COMPLETE ===")
