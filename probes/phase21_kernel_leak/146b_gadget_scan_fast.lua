-- CRASH_CLASS: LOW
-- PROBE 146b: Fast gadget scan for RDTSC, PREFETCH, POP_RDX, MOV_STORE
--
-- Scans eboot in 128KB chunks at 4-byte alignment, checks all byte
-- positions in each dword. Much faster than 2-byte step scan.

print("=== PROBE 146b: FAST GADGET SCAN ===")

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
local function wd(addr, val) memory.write_dword(addr, val) end

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))
print("eboot=" .. string.format("0x%X%08X", ehi, elo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", ehi, elo + off))
end

-- Targets (first found only):
local g_rdtsc_ret = nil     -- 0F 31 C3 (rdtsc; ret)
local g_pop_rdx = nil       -- 5A C3 (pop rdx; ret)
local g_mov_store_q = nil   -- 48 89 07 C3 (mov [rdi],rax; ret)
local g_mov_store_d = nil   -- 89 07 C3 (mov [rdi],eax; ret)
local g_prefetch = nil      -- 0F 18 xx (prefetch family)
local g_rdtsc_any = nil     -- 0F 31 (rdtsc at any position)
local g_pop_r8 = nil        -- 41 58 C3 (pop r8; ret)

local found_count = 0
local needed = 7

-- Scan 3MB at 4-byte steps
-- Read qword = 8 bytes, check all positions
local scan_end = 0x300000
print("scanning " .. string.format("0x%X", scan_end) .. " bytes...")

for off = 0, scan_end - 8, 4 do
    if found_count >= needed then break end

    local d1 = safe_rd(eaddr(off))
    local d2 = safe_rd(eaddr(off + 4))
    if d1 == nil then break end
    if d2 == nil then d2 = 0 end

    local b = {}
    b[0] = d1 % 256
    b[1] = math.floor(d1 / 256) % 256
    b[2] = math.floor(d1 / 65536) % 256
    b[3] = math.floor(d1 / 16777216) % 256
    b[4] = d2 % 256
    b[5] = math.floor(d2 / 256) % 256
    b[6] = math.floor(d2 / 65536) % 256
    b[7] = math.floor(d2 / 16777216) % 256

    for i = 0, 5 do
        -- RDTSC;RET = 0F 31 C3
        if not g_rdtsc_ret and b[i] == 0x0F and b[i+1] == 0x31 and b[i+2] == 0xC3 then
            g_rdtsc_ret = off + i
            found_count = found_count + 1
            print("RDTSC;RET at eboot+0x" .. string.format("%X", g_rdtsc_ret))
        end
        -- POP RDX;RET = 5A C3
        if not g_pop_rdx and b[i] == 0x5A and b[i+1] == 0xC3 then
            g_pop_rdx = off + i
            found_count = found_count + 1
            print("POP_RDX;RET at eboot+0x" .. string.format("%X", g_pop_rdx))
        end
        -- POP R8;RET = 41 58 C3
        if not g_pop_r8 and b[i] == 0x41 and b[i+1] == 0x58 and b[i+2] == 0xC3 then
            g_pop_r8 = off + i
            found_count = found_count + 1
            print("POP_R8;RET at eboot+0x" .. string.format("%X", g_pop_r8))
        end
    end

    for i = 0, 4 do
        -- MOV [RDI],RAX;RET = 48 89 07 C3
        if not g_mov_store_q and b[i] == 0x48 and b[i+1] == 0x89 and b[i+2] == 0x07 and b[i+3] == 0xC3 then
            g_mov_store_q = off + i
            found_count = found_count + 1
            print("MOV_STORE_Q at eboot+0x" .. string.format("%X", g_mov_store_q))
        end
    end

    for i = 0, 5 do
        -- MOV [RDI],EAX;RET = 89 07 C3
        if not g_mov_store_d and b[i] == 0x89 and b[i+1] == 0x07 and b[i+2] == 0xC3 then
            g_mov_store_d = off + i
            found_count = found_count + 1
            print("MOV_STORE_D at eboot+0x" .. string.format("%X", g_mov_store_d))
        end
    end

    for i = 0, 6 do
        -- RDTSC = 0F 31 (without immediate RET)
        if not g_rdtsc_any and b[i] == 0x0F and b[i+1] == 0x31 then
            g_rdtsc_any = off + i
            found_count = found_count + 1
            print("RDTSC_ANY at eboot+0x" .. string.format("%X", g_rdtsc_any))
        end
    end

    for i = 0, 5 do
        -- PREFETCH [reg] = 0F 18 ModRM
        if not g_prefetch and b[i] == 0x0F and b[i+1] == 0x18 then
            local modrm = b[i+2]
            if modrm then
                local reg = math.floor(modrm / 8) % 8
                if reg <= 3 then
                    g_prefetch = off + i
                    found_count = found_count + 1
                    print("PREFETCH at eboot+0x" .. string.format("%X", g_prefetch) ..
                        " modrm=0x" .. string.format("%02X", modrm))
                end
            end
        end
    end
end

print("")
print("--- Summary ---")
print("rdtsc_ret: " .. (g_rdtsc_ret and string.format("+0x%X", g_rdtsc_ret) or "NOT FOUND"))
print("rdtsc_any: " .. (g_rdtsc_any and string.format("+0x%X", g_rdtsc_any) or "NOT FOUND"))
print("pop_rdx:   " .. (g_pop_rdx and string.format("+0x%X", g_pop_rdx) or "NOT FOUND"))
print("pop_r8:    " .. (g_pop_r8 and string.format("+0x%X", g_pop_r8) or "NOT FOUND"))
print("mov_q:     " .. (g_mov_store_q and string.format("+0x%X", g_mov_store_q) or "NOT FOUND"))
print("mov_d:     " .. (g_mov_store_d and string.format("+0x%X", g_mov_store_d) or "NOT FOUND"))
print("prefetch:  " .. (g_prefetch and string.format("+0x%X", g_prefetch) or "NOT FOUND"))

-- Verify found gadgets by reading bytes
if g_rdtsc_ret then
    local v = safe_rd(eaddr(g_rdtsc_ret))
    print("rdtsc_ret verify: 0x" .. string.format("%08X", v or 0))
end
if g_pop_rdx then
    local v = safe_rd(eaddr(g_pop_rdx))
    print("pop_rdx verify: 0x" .. string.format("%08X", v or 0))
end
if g_mov_store_q then
    local v = safe_rd(eaddr(g_mov_store_q))
    print("mov_q verify: 0x" .. string.format("%08X", v or 0))
end

print("")
print("=== PROBE 146b COMPLETE ===")
