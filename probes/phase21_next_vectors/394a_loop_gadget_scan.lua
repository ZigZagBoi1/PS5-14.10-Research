-- CRASH_CLASS: LOW
-- PROBE 394a: scan eboot .text for loop gadgets
--
-- Need: leave;ret (C9 C3), pop rsp;ret (5C C3),
-- xchg rax,rsp (48 94), mov rsp,rbp (48 89 EC)
-- Also look for pop rbp;ret (5D C3) standalone

print("=== PROBE 394a: loop gadget scan ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local eb_sz_lo = rd(N(info) + 0x110) or 0
local eb_sz_hi = rd(N(info) + 0x114) or 0
local eb_size = eb_sz_hi * 0x100000000 + eb_sz_lo
print(string.format("eboot=%X_%08X size=%X", eb_hi, eb_lo, eb_size))

-- Scan window: first 4.6MB of eboot .text (RX, safe to read)
local SCAN = math.min(eb_size, 0x480000)
print(string.format("scanning %X bytes...", SCAN))

local base = eb_hi * 0x100000000 + eb_lo

-- Patterns to find
local leave_ret = 0  -- C9 C3
local pop_rsp_ret = 0  -- 5C C3
local pop_rbp_ret = 0  -- 5D C3
local xchg_rax_rsp = 0  -- 48 94 C3
local mov_rsp_rbp = 0  -- 48 89 EC C3

local results = {}

for off = 0, SCAN - 4, 1 do
    local d = rd(base + off)
    if d == nil then break end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256

    -- leave;ret = C9 C3
    if b0 == 0xC9 and b1 == 0xC3 then
        leave_ret = leave_ret + 1
        if leave_ret <= 5 then
            table.insert(results, string.format("leave;ret +%06X", off))
        end
    end

    -- pop rsp;ret = 5C C3
    if b0 == 0x5C and b1 == 0xC3 then
        pop_rsp_ret = pop_rsp_ret + 1
        if pop_rsp_ret <= 5 then
            table.insert(results, string.format("pop_rsp;ret +%06X", off))
        end
    end

    -- pop rbp;ret = 5D C3
    if b0 == 0x5D and b1 == 0xC3 then
        pop_rbp_ret = pop_rbp_ret + 1
        if pop_rbp_ret <= 3 then
            table.insert(results, string.format("pop_rbp;ret +%06X", off))
        end
    end

    -- xchg rax,rsp;ret = 48 94 C3
    if b0 == 0x48 and b1 == 0x94 and b2 == 0xC3 then
        xchg_rax_rsp = xchg_rax_rsp + 1
        table.insert(results, string.format("xchg_rax_rsp;ret +%06X", off))
    end

    -- mov rsp,rbp;ret = 48 89 EC C3
    if b0 == 0x48 and b1 == 0x89 and b2 == 0xEC and b3 == 0xC3 then
        mov_rsp_rbp = mov_rsp_rbp + 1
        table.insert(results, string.format("mov_rsp_rbp;ret +%06X", off))
    end

    -- Also: jmp [rax] = FF 20 (for indirect jumps)
    -- and: push rsp;ret = 54 C3
end

print(string.format("leave;ret=%d pop_rsp;ret=%d pop_rbp;ret=%d",
    leave_ret, pop_rsp_ret, pop_rbp_ret))
print(string.format("xchg_rax_rsp=%d mov_rsp_rbp=%d",
    xchg_rax_rsp, mov_rsp_rbp))

for _, r in ipairs(results) do
    print("  " .. r)
end

-- Also scan for: pop rsp; pop rbp; ret (5C 5D C3)
-- and: add rsp, N; ret patterns
local pop_rsp_rbp = 0
local add_rsp = 0
for off = 0, SCAN - 4, 1 do
    local d = rd(base + off)
    if d == nil then break end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256

    if b0 == 0x5C and b1 == 0x5D and b2 == 0xC3 then
        pop_rsp_rbp = pop_rsp_rbp + 1
        if pop_rsp_rbp <= 3 then
            print(string.format("  pop_rsp;pop_rbp;ret +%06X", off))
        end
    end

    -- add rsp, imm8; ret = 48 83 C4 XX C3
    if b0 == 0x48 and b1 == 0x83 and b2 == 0xC4 then
        local d2 = rd(base + off + 3)
        if d2 and (d2 % 256) == 0xC3 then
            -- don't count, just note a few
        end
    end
end

print(string.format("pop_rsp;pop_rbp;ret=%d", pop_rsp_rbp))
print("")
print("=== 394a COMPLETE ===")
