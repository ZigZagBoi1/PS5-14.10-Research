-- CRASH_CLASS: LOW
-- PROBE 272a: scan eboot .text for multi-argument ROP gadgets
--
-- Context: 271g confirmed child thread single-arg syscalls via ROP
-- using pop_rax_ret (+0x992) and pop_rdi_rbp_ret (+0x169).
-- To enable multi-argument syscalls we need:
--   pop_rsi_ret (5E C3) or pop_rsi_r15_ret (5E 41 5F C3) — arg2
--   pop_rdx_ret (5A C3) or pop_rdx_rbx_ret (5A 5B C3) — arg3
--   pop_rcx_ret (59 C3) — arg4 (FreeBSD syscall ABI uses rcx for arg4)
--   pop_r8_ret  (41 58 C3) — arg5
--   pop_r9_ret  (41 59 C3) — arg6
-- Also useful compound gadgets:
--   pop_rsi_rdx_ret (5E 5A C3) — arg2+arg3 in one
--   mov_rsi_rdi_call_rax or similar for chaining
--
-- Scans the full eboot .text (RX, readable) in 4KB chunks.
-- Reports ALL matches with offsets.

print("=== PROBE 272a: multi-arg ROP gadget scan ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Get eboot base + text size via dynlib_get_info (handle 0 = eboot)
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)

local tlo = rd(N(ib) + 0x108) or 0
local thi = rd(N(ib) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end

local szlo = rd(N(ib) + 0x110) or 0
if szlo < 0 then szlo = szlo + 0x100000000 end

local text_size = szlo  -- text is < 4GB
print(string.format("eboot_text=0x%X%08X  size=0x%X", thi, tlo, text_size))

if text_size == 0 then
    print("WARNING: zero text size, using 4.8MB default")
    text_size = 0x494000
elseif text_size > 0x800000 then
    print("WARNING: text > 8MB, capping at 8MB")
    text_size = 0x800000
end

local base = thi * 0x100000000 + tlo
print(string.format("scanning %d bytes (%.1f MB)", text_size, text_size / 1048576))

-- Scan in 4KB chunks, read byte-by-byte via dwords
-- We look for specific byte patterns

local base = N(eboot_base)
local scan_end = base + text_size
if base == 0 then
    print("ABORT: eboot base is 0")
    return
end

-- Gadget patterns to find
-- Each entry: {name, bytes_before_ret, description}
-- We scan for C3 (ret) and check preceding bytes
local gadgets = {
    -- 2-byte gadgets (1 byte + C3)
    {name = "pop_rsi_ret",     pre = {0x5E},           desc = "arg2"},
    {name = "pop_rdx_ret",     pre = {0x5A},           desc = "arg3"},
    {name = "pop_rcx_ret",     pre = {0x59},           desc = "arg4"},
    {name = "pop_rbx_ret",     pre = {0x5B},           desc = "rbx"},
    {name = "pop_rdi_ret",     pre = {0x5F},           desc = "arg1 (clean)"},

    -- 3-byte gadgets (2 bytes + C3)
    {name = "pop_r8_ret",      pre = {0x41, 0x58},     desc = "arg5"},
    {name = "pop_r9_ret",      pre = {0x41, 0x59},     desc = "arg6"},
    {name = "pop_r10_ret",     pre = {0x41, 0x5A},     desc = "r10"},
    {name = "pop_r11_ret",     pre = {0x41, 0x5B},     desc = "r11"},
    {name = "pop_r12_ret",     pre = {0x41, 0x5C},     desc = "r12"},
    {name = "pop_r13_ret",     pre = {0x41, 0x5D},     desc = "r13"},
    {name = "pop_r14_ret",     pre = {0x41, 0x5E},     desc = "r14"},
    {name = "pop_r15_ret",     pre = {0x41, 0x5F},     desc = "r15"},
    {name = "pop_rsi_rdx_ret", pre = {0x5E, 0x5A},     desc = "arg2+arg3"},
    {name = "pop_rdx_rsi_ret", pre = {0x5A, 0x5E},     desc = "arg3+arg2"},
    {name = "pop_rdi_rsi_ret", pre = {0x5F, 0x5E},     desc = "arg1+arg2"},
    {name = "pop_rdx_rbx_ret", pre = {0x5A, 0x5B},     desc = "arg3+rbx"},

    -- 4-byte gadgets (3 bytes + C3)
    {name = "pop_rdi_rsi_rdx_ret", pre = {0x5F, 0x5E, 0x5A}, desc = "arg1+2+3"},
    {name = "pop_rsi_rdx_rcx_ret", pre = {0x5E, 0x5A, 0x59}, desc = "arg2+3+4"},
    {name = "pop_rsi_r15_ret",     pre = {0x5E, 0x41, 0x5F}, desc = "arg2+r15"},

    -- Pop with rbp (common in function epilogues)
    {name = "pop_rsi_rbp_ret",     pre = {0x5E, 0x5D},       desc = "arg2+rbp"},
    {name = "pop_rdx_rbp_ret",     pre = {0x5A, 0x5D},       desc = "arg3+rbp"},
    {name = "pop_rcx_rbp_ret",     pre = {0x59, 0x5D},       desc = "arg4+rbp"},
    {name = "pop_rbx_rbp_ret",     pre = {0x5B, 0x5D},       desc = "rbx+rbp"},
    {name = "pop_rsi_rbx_rbp_ret", pre = {0x5E, 0x5B, 0x5D}, desc = "arg2+rbx+rbp"},
    {name = "pop_rdx_rbx_rbp_ret", pre = {0x5A, 0x5B, 0x5D}, desc = "arg3+rbx+rbp"},

    -- 5-byte compound
    {name = "pop_r12_r13_ret",     pre = {0x41, 0x5C, 0x41, 0x5D}, desc = "r12+r13"},
    {name = "pop_r14_r15_ret",     pre = {0x41, 0x5E, 0x41, 0x5F}, desc = "r14+r15"},

    -- Longer epilogue patterns
    {name = "pop_rbx_r12_rbp_ret",       pre = {0x5B, 0x41, 0x5C, 0x5D},       desc = "rbx+r12+rbp"},
    {name = "pop_rbx_r12_r13_rbp_ret",   pre = {0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x5D}, desc = "rbx+r12+r13+rbp"},
    {name = "pop_rbx_r14_r15_rbp_ret",   pre = {0x5B, 0x41, 0x5E, 0x41, 0x5F, 0x5D}, desc = "rbx+r14+r15+rbp"},
}

-- Read bytes at an address, using dword reads
local byte_cache = {}
local cache_base_addr = nil
local cache_dwords = nil

local function read_byte(addr)
    -- Which dword contains this byte?
    local dw_addr = addr - (addr % 4)
    local byte_off = addr % 4

    if cache_dwords and dw_addr >= cache_base_addr and dw_addr < cache_base_addr + 4096 then
        local idx = math.floor((dw_addr - cache_base_addr) / 4)
        local dw = cache_dwords[idx]
        if dw then
            local shift = byte_off * 8
            return math.floor(dw / (2 ^ shift)) % 256
        end
    end
    return nil
end

-- Results
local found = {}

print(string.format("[A] scanning 0x%X bytes for %d gadget patterns...", text_size, #gadgets))

local chunk_size = 4096
local chunks_done = 0
local total_chunks = math.ceil(text_size / chunk_size)

for chunk_start = base, scan_end - 1, chunk_size do
    if not alive() then print("DEAD"); break end

    -- Read this chunk into cache
    cache_base_addr = chunk_start
    cache_dwords = {}
    local chunk_end = math.min(chunk_start + chunk_size, scan_end)

    for addr = chunk_start, chunk_end - 1, 4 do
        local dw = rd(addr)
        if dw then
            cache_dwords[math.floor((addr - chunk_start) / 4)] = dw
        end
    end

    -- Scan for C3 (ret) bytes in this chunk
    for addr = chunk_start, chunk_end - 1 do
        local b = read_byte(addr)
        if b == 0xC3 then
            -- Check each gadget pattern
            for _, g in ipairs(gadgets) do
                local pre = g.pre
                local match = true
                local start_addr = addr - #pre

                if start_addr >= base then
                    for i = 1, #pre do
                        local pb = read_byte(start_addr + i - 1)
                        if pb ~= pre[i] then
                            match = false
                            break
                        end
                    end

                    if match then
                        local offset = start_addr - base
                        if not found[g.name] then
                            found[g.name] = {}
                        end
                        local list = found[g.name]
                        if #list < 5 then  -- Keep first 5 of each
                            list[#list + 1] = offset
                        end
                    end
                end
            end
        end
    end

    chunks_done = chunks_done + 1
    if chunks_done % 256 == 0 then
        collectgarbage("collect")
        print(string.format("  progress: %d/%d chunks (%.0f%%)", chunks_done, total_chunks, chunks_done / total_chunks * 100))
    end
end

-- Report results
print("")
print("[B] RESULTS — gadgets found:")
print("")

-- Critical gadgets for multi-arg syscalls
local critical = {"pop_rsi_ret", "pop_rdx_ret", "pop_rcx_ret", "pop_r8_ret", "pop_r9_ret",
                   "pop_rdi_ret", "pop_rsi_rbp_ret", "pop_rdx_rbp_ret", "pop_rcx_rbp_ret",
                   "pop_rsi_rdx_ret", "pop_rdx_rsi_ret", "pop_rdi_rsi_ret", "pop_rdi_rsi_rdx_ret",
                   "pop_rsi_rdx_rcx_ret", "pop_rdx_rbx_ret", "pop_rsi_rbx_rbp_ret", "pop_rdx_rbx_rbp_ret"}

print("=== CRITICAL (syscall args) ===")
for _, name in ipairs(critical) do
    local list = found[name]
    if list and #list > 0 then
        local offsets = {}
        for _, off in ipairs(list) do
            offsets[#offsets + 1] = string.format("+0x%X", off)
        end
        -- Find description
        local desc = ""
        for _, g in ipairs(gadgets) do
            if g.name == name then desc = g.desc; break end
        end
        print(string.format("  %-30s [%s] %s", name, desc, table.concat(offsets, ", ")))
    end
end

print("")
print("=== ALL FOUND ===")
local sorted_names = {}
for name, _ in pairs(found) do
    sorted_names[#sorted_names + 1] = name
end
table.sort(sorted_names)

for _, name in ipairs(sorted_names) do
    local list = found[name]
    local offsets = {}
    for _, off in ipairs(list) do
        offsets[#offsets + 1] = string.format("+0x%X", off)
    end
    local desc = ""
    for _, g in ipairs(gadgets) do
        if g.name == name then desc = g.desc; break end
    end
    print(string.format("  %-30s [%s] count=%d first=%s", name, desc, #list, offsets[1]))
    if #list > 1 then
        print(string.format("    all: %s", table.concat(offsets, ", ")))
    end
end

-- Summary: what syscall shapes can we build?
print("")
print("[C] CAPABILITY ASSESSMENT:")
local has_rdi = found["pop_rdi_ret"] or found["pop_rdi_rsi_ret"] or found["pop_rdi_rsi_rdx_ret"]
local has_rsi = found["pop_rsi_ret"] or found["pop_rsi_rbp_ret"] or found["pop_rsi_rdx_ret"] or found["pop_rdi_rsi_ret"]
local has_rdx = found["pop_rdx_ret"] or found["pop_rdx_rbp_ret"] or found["pop_rdx_rbx_ret"] or found["pop_rsi_rdx_ret"]
local has_rcx = found["pop_rcx_ret"] or found["pop_rcx_rbp_ret"]
local has_r8  = found["pop_r8_ret"]
local has_r9  = found["pop_r9_ret"]

print(string.format("  rdi (arg1): %s", has_rdi and "YES" or "NO"))
print(string.format("  rsi (arg2): %s", has_rsi and "YES" or "NO"))
print(string.format("  rdx (arg3): %s", has_rdx and "YES" or "NO"))
print(string.format("  rcx (arg4): %s", has_rcx and "YES" or "NO"))
print(string.format("  r8  (arg5): %s", has_r8 and "YES" or "NO"))
print(string.format("  r9  (arg6): %s", has_r9 and "YES" or "NO"))

local max_args = 0
if has_rdi then max_args = 1 end
if has_rdi and has_rsi then max_args = 2 end
if has_rdi and has_rsi and has_rdx then max_args = 3 end
if has_rdi and has_rsi and has_rdx and has_rcx then max_args = 4 end
if has_rdi and has_rsi and has_rdx and has_rcx and has_r8 then max_args = 5 end
if has_rdi and has_rsi and has_rdx and has_rcx and has_r8 and has_r9 then max_args = 6 end
print(string.format("  MAX ARGS from child thread: %d", max_args))

-- Known gadgets from earlier work
print("")
print("[D] KNOWN GADGETS (reference):")
print("  pop_rax_ret:     eboot+0x992  (58 C3)")
print("  pop_rdi_rbp_ret: eboot+0x169  (5F 5D C3)")
print("  bare_ret:        eboot+0x42   (C3)")
print("  fn_addr (stub):  libkernel XO (syscall entry)")

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 272a COMPLETE ===")
