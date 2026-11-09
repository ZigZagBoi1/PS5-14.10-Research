-- CRASH_CLASS: LOW
-- PROBE 394c: wide eboot scan for stack-pivot / loop gadgets
--
-- Scan 2MB of eboot for: leave;ret, pop_rsp;ret, xchg patterns,
-- push_rbp;ret, jmp_rax, call_rax, and any REX mov rsp variants.

print("=== PROBE 394c: wide gadget scan ===")

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

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local base = eb_hi * 0x100000000 + eb_lo
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

-- Counters
local leave_n, pop_rsp_n = 0, 0
local xchg_n, mov_rsp_n = 0, 0
local jmp_rax_n, call_rax_n = 0, 0
local push_rbp_n = 0

-- First 5 hits each
local leave_h, pop_rsp_h = {}, {}
local xchg_h, mov_rsp_h = {}, {}
local jmp_rax_h, call_rax_h = {}, {}
local push_rbp_h = {}

-- Scan 2MB in 128 chunks of 16KB
local TOTAL = 0x200000
local CHUNK = 0x4000
local chunks = TOTAL / CHUNK
print(string.format("scan %dKB (%d chunks)", TOTAL / 1024, chunks))

for c = 0, chunks - 1 do
    local off0 = c * CHUNK
    local prev_b3 = nil
    for off = off0, off0 + CHUNK - 4, 4 do
        local d = rd(base + off)
        if d == nil then break end
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256

        -- Boundary check
        if prev_b3 then
            if prev_b3 == 0xC9 and b0 == 0xC3 then
                leave_n = leave_n + 1
                if #leave_h < 5 then table.insert(leave_h, off - 1) end
            end
            if prev_b3 == 0x5C and b0 == 0xC3 then
                pop_rsp_n = pop_rsp_n + 1
                if #pop_rsp_h < 5 then table.insert(pop_rsp_h, off - 1) end
            end
            -- FF E0 = jmp rax
            if prev_b3 == 0xFF and b0 == 0xE0 then
                jmp_rax_n = jmp_rax_n + 1
                if #jmp_rax_h < 5 then table.insert(jmp_rax_h, off - 1) end
            end
            -- FF D0 = call rax
            if prev_b3 == 0xFF and b0 == 0xD0 then
                call_rax_n = call_rax_n + 1
                if #call_rax_h < 5 then table.insert(call_rax_h, off - 1) end
            end
        end

        -- Within dword: check positions 0-1, 1-2, 2-3
        local function chk2(a, b, cnt_name, hit_tbl)
            if b0 == a and b1 == b then
                return 1, off
            elseif b1 == a and b2 == b then
                return 1, off + 1
            elseif b2 == a and b3 == b then
                return 1, off + 2
            end
            return 0, nil
        end

        -- leave;ret C9 C3
        local inc, pos = chk2(0xC9, 0xC3)
        if inc > 0 then
            leave_n = leave_n + inc
            if #leave_h < 5 then table.insert(leave_h, pos) end
        end

        -- pop rsp;ret 5C C3
        inc, pos = chk2(0x5C, 0xC3)
        if inc > 0 then
            pop_rsp_n = pop_rsp_n + inc
            if #pop_rsp_h < 5 then table.insert(pop_rsp_h, pos) end
        end

        -- jmp rax FF E0
        inc, pos = chk2(0xFF, 0xE0)
        if inc > 0 then
            jmp_rax_n = jmp_rax_n + inc
            if #jmp_rax_h < 5 then table.insert(jmp_rax_h, pos) end
        end

        -- call rax FF D0
        inc, pos = chk2(0xFF, 0xD0)
        if inc > 0 then
            call_rax_n = call_rax_n + inc
            if #call_rax_h < 5 then table.insert(call_rax_h, pos) end
        end

        -- 3-byte patterns: check within dword and boundary
        -- xchg rax,rsp;ret = 48 94 C3
        if b0 == 0x48 and b1 == 0x94 and b2 == 0xC3 then
            xchg_n = xchg_n + 1
            if #xchg_h < 5 then table.insert(xchg_h, off) end
        end
        if b1 == 0x48 and b2 == 0x94 and b3 == 0xC3 then
            xchg_n = xchg_n + 1
            if #xchg_h < 5 then table.insert(xchg_h, off + 1) end
        end

        -- mov rsp,rbp;ret = 48 89 EC C3
        if b0 == 0x48 and b1 == 0x89 and b2 == 0xEC and b3 == 0xC3 then
            mov_rsp_n = mov_rsp_n + 1
            if #mov_rsp_h < 5 then table.insert(mov_rsp_h, off) end
        end

        -- push rbp;ret = 55 C3
        inc, pos = chk2(0x55, 0xC3)
        if inc > 0 then
            push_rbp_n = push_rbp_n + inc
            if #push_rbp_h < 3 then table.insert(push_rbp_h, pos) end
        end

        prev_b3 = b3
    end
end

print(string.format("leave;ret=%d pop_rsp;ret=%d", leave_n, pop_rsp_n))
print(string.format("xchg_rax_rsp=%d mov_rsp_rbp=%d", xchg_n, mov_rsp_n))
print(string.format("jmp_rax=%d call_rax=%d push_rbp=%d", jmp_rax_n, call_rax_n, push_rbp_n))

for _, o in ipairs(leave_h) do print(string.format("  LEAVE +%06X", o)) end
for _, o in ipairs(pop_rsp_h) do print(string.format("  POP_RSP +%06X", o)) end
for _, o in ipairs(xchg_h) do print(string.format("  XCHG +%06X", o)) end
for _, o in ipairs(mov_rsp_h) do print(string.format("  MOV_RSP +%06X", o)) end
for _, o in ipairs(jmp_rax_h) do print(string.format("  JMP_RAX +%06X", o)) end
for _, o in ipairs(call_rax_h) do print(string.format("  CALL_RAX +%06X", o)) end
for _, o in ipairs(push_rbp_h) do print(string.format("  PUSH_RBP +%06X", o)) end

print("=== 394c COMPLETE ===")
