-- CRASH_CLASS: LOW
-- PROBE 1403l: search for loop gadgets in eboot
--
-- For timer thread (Spectre timing), need:
-- 1. pop rbp; ret       (5D C3)
-- 2. leave; ret          (C9 C3)
-- 3. inc [rdi]; ret      (FF 07 C3) or add [rdi],1; ret (83 07 01 C3)
-- 4. lock inc [rdi]; ret (F0 FF 07 C3)
-- 5. inc qword [rdi]; ret (48 FF 07 C3) — 64-bit inc
-- 6. add qword [rdi],1; ret (48 83 07 01 C3) — 64-bit add
-- 7. sub rsp,N; ret or add rsp,N; ret patterns
-- 8. xchg rsp,rbp / mov rsp,rbp patterns

print("=== 1403l: loop gadget search ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) memory.write_dword(a, v) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local ebn = N(uint64(string.format("0x%X%08X", eb_hi, eb_lo)))
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Scan full eboot (0 to 0x494000)
-- For speed: check 4KB pages, skip guard page area if needed
local MAX = 0x494000

-- Results
local pop_rbp_ret = {}   -- 5D C3
local leave_ret = {}     -- C9 C3
local inc_rdi_ret = {}   -- FF 07 C3
local add_rdi_1_ret = {} -- 83 07 01 C3
local lock_inc = {}      -- F0 FF 07 C3
local inc64_rdi = {}     -- 48 FF 07 C3
local add64_rdi_1 = {}   -- 48 83 07 01 C3
local xadd_rdi = {}      -- F0 0F C1 07 C3 (lock xadd [rdi],eax; ret)

local scanned = 0
local prev = nil
for page = 0, MAX - 0x1000, 0x1000 do
    local test = rd(ebn + page)
    if test then
        for off = page, page + 0x1000 - 4, 4 do
            local d = rd(ebn + off)
            if not d then break end

            local b0 = d % 256
            local b1 = math.floor(d / 256) % 256
            local b2 = math.floor(d / 65536) % 256
            local b3 = math.floor(d / 16777216) % 256

            -- Check within dword: 2-byte patterns at pos 0,1,2
            -- pop rbp;ret = 5D C3
            if b0 == 0x5D and b1 == 0xC3 then pop_rbp_ret[#pop_rbp_ret+1] = off end
            if b1 == 0x5D and b2 == 0xC3 then pop_rbp_ret[#pop_rbp_ret+1] = off+1 end
            if b2 == 0x5D and b3 == 0xC3 then pop_rbp_ret[#pop_rbp_ret+1] = off+2 end

            -- leave;ret = C9 C3
            if b0 == 0xC9 and b1 == 0xC3 then leave_ret[#leave_ret+1] = off end
            if b1 == 0xC9 and b2 == 0xC3 then leave_ret[#leave_ret+1] = off+1 end
            if b2 == 0xC9 and b3 == 0xC3 then leave_ret[#leave_ret+1] = off+2 end

            -- 3-byte: FF 07 C3 = inc [rdi]; ret
            if b0 == 0xFF and b1 == 0x07 and b2 == 0xC3 then inc_rdi_ret[#inc_rdi_ret+1] = off end
            if b1 == 0xFF and b2 == 0x07 and b3 == 0xC3 then inc_rdi_ret[#inc_rdi_ret+1] = off+1 end

            -- 4-byte: 83 07 01 C3 = add dword [rdi],1; ret
            if b0 == 0x83 and b1 == 0x07 and b2 == 0x01 and b3 == 0xC3 then
                add_rdi_1_ret[#add_rdi_1_ret+1] = off
            end

            -- 4-byte: F0 FF 07 C3 = lock inc dword [rdi]; ret
            if b0 == 0xF0 and b1 == 0xFF and b2 == 0x07 and b3 == 0xC3 then
                lock_inc[#lock_inc+1] = off
            end

            -- 4-byte: 48 FF 07 C3 = inc qword [rdi]; ret
            if b0 == 0x48 and b1 == 0xFF and b2 == 0x07 and b3 == 0xC3 then
                inc64_rdi[#inc64_rdi+1] = off
            end

            -- Cross-boundary checks with prev dword
            if prev then
                local p0 = prev % 256
                local p1 = math.floor(prev / 256) % 256
                local p2 = math.floor(prev / 65536) % 256
                local p3 = math.floor(prev / 16777216) % 256

                -- 5D C3 across boundary
                if p3 == 0x5D and b0 == 0xC3 then pop_rbp_ret[#pop_rbp_ret+1] = off-1 end
                -- C9 C3 across boundary
                if p3 == 0xC9 and b0 == 0xC3 then leave_ret[#leave_ret+1] = off-1 end

                -- FF 07 C3 across boundary
                if p2 == 0xFF and p3 == 0x07 and b0 == 0xC3 then inc_rdi_ret[#inc_rdi_ret+1] = off-2 end
                if p3 == 0xFF and b0 == 0x07 and b1 == 0xC3 then inc_rdi_ret[#inc_rdi_ret+1] = off-1 end

                -- 83 07 01 C3 across boundary
                if p1 == 0x83 and p2 == 0x07 and p3 == 0x01 and b0 == 0xC3 then
                    add_rdi_1_ret[#add_rdi_1_ret+1] = off-3
                end
                if p2 == 0x83 and p3 == 0x07 and b0 == 0x01 and b1 == 0xC3 then
                    add_rdi_1_ret[#add_rdi_1_ret+1] = off-2
                end
                if p3 == 0x83 and b0 == 0x07 and b1 == 0x01 and b2 == 0xC3 then
                    add_rdi_1_ret[#add_rdi_1_ret+1] = off-1
                end

                -- F0 FF 07 C3 across boundary
                if p1 == 0xF0 and p2 == 0xFF and p3 == 0x07 and b0 == 0xC3 then
                    lock_inc[#lock_inc+1] = off-3
                end
                if p2 == 0xF0 and p3 == 0xFF and b0 == 0x07 and b1 == 0xC3 then
                    lock_inc[#lock_inc+1] = off-2
                end
                if p3 == 0xF0 and b0 == 0xFF and b1 == 0x07 and b2 == 0xC3 then
                    lock_inc[#lock_inc+1] = off-1
                end

                -- 48 FF 07 C3 across boundary
                if p1 == 0x48 and p2 == 0xFF and p3 == 0x07 and b0 == 0xC3 then
                    inc64_rdi[#inc64_rdi+1] = off-3
                end
                if p2 == 0x48 and p3 == 0xFF and b0 == 0x07 and b1 == 0xC3 then
                    inc64_rdi[#inc64_rdi+1] = off-2
                end
                if p3 == 0x48 and b0 == 0xFF and b1 == 0x07 and b2 == 0xC3 then
                    inc64_rdi[#inc64_rdi+1] = off-1
                end
            end
            prev = d
        end
        scanned = scanned + 0x1000
    end
end

print(string.format("scanned: %d KB", scanned / 1024))
print("")
print(string.format("pop rbp; ret (5D C3): %d", #pop_rbp_ret))
if #pop_rbp_ret > 0 then
    print(string.format("  first: +0x%06X", pop_rbp_ret[1]))
end

print(string.format("leave; ret (C9 C3): %d", #leave_ret))
if #leave_ret > 0 then
    print(string.format("  first: +0x%06X", leave_ret[1]))
end

print(string.format("inc [rdi]; ret (FF 07 C3): %d", #inc_rdi_ret))
for i = 1, math.min(#inc_rdi_ret, 5) do
    print(string.format("  +0x%06X", inc_rdi_ret[i]))
end

print(string.format("add dword [rdi],1; ret (83 07 01 C3): %d", #add_rdi_1_ret))
for i = 1, math.min(#add_rdi_1_ret, 5) do
    print(string.format("  +0x%06X", add_rdi_1_ret[i]))
end

print(string.format("lock inc [rdi]; ret (F0 FF 07 C3): %d", #lock_inc))
for i = 1, math.min(#lock_inc, 5) do
    print(string.format("  +0x%06X", lock_inc[i]))
end

print(string.format("inc qword [rdi]; ret (48 FF 07 C3): %d", #inc64_rdi))
for i = 1, math.min(#inc64_rdi, 5) do
    print(string.format("  +0x%06X", inc64_rdi[i]))
end

print("")
print("=== 1403l DONE ===")
