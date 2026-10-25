-- CRASH_CLASS: LOW
-- PROBE 530i: Find GnmDriver submit call site in eboot
--
-- 530h confirmed: ioctl 0xC0108102 accepts but GPU never executes.
-- The GnmDriver's submit function does the ioctl + doorbell write.
-- The eboot calls GnmDriver submit via GOT. Eboot .text is RX (readable).
--
-- Strategy:
-- 1. Find eboot's GOT by scanning .data for module text pointers
-- 2. Scan eboot .text for CALL [rip+disp] instructions that reference GOT
--    entries pointing to GnmDriver .text
-- 3. Find the submit context (what registers/globals are set up before call)
-- 4. Map GnmDriver .data globals that hold doorbell/ring state

print("=== PROBE 530i: EBOOT SUBMIT HUNT ===")
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
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
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

-- ============================================================
-- [A] Get module info
-- ============================================================
print("")
print("[A] Module info")

local sc_593 = mk(593)

local function get_mod(handle)
    local ib = memory.alloc(0x200)
    wd(N(ib), 0x160)
    pcall(function() sc_593(uint64(handle), ib) end)
    local text_lo = rd(N(ib) + 0x108) or 0
    local text_hi = rd(N(ib) + 0x10C) or 0
    if text_lo < 0 then text_lo = text_lo + 0x100000000 end
    if text_hi < 0 then text_hi = text_hi + 0x100000000 end
    local text_size = rd(N(ib) + 0x110) or 0
    if text_size < 0 then text_size = text_size + 0x100000000 end
    local data_lo = rd(N(ib) + 0x120) or 0
    local data_hi = rd(N(ib) + 0x124) or 0
    if data_lo < 0 then data_lo = data_lo + 0x100000000 end
    if data_hi < 0 then data_hi = data_hi + 0x100000000 end
    local data_size = rd(N(ib) + 0x128) or 0
    if data_size < 0 then data_size = data_size + 0x100000000 end
    return {
        text_lo = text_lo, text_hi = text_hi, text_size = text_size,
        data_lo = data_lo, data_hi = data_hi, data_size = data_size,
        text_base = text_hi * 0x100000000 + text_lo,
        data_base = data_hi * 0x100000000 + data_lo,
    }
end

local eboot = get_mod(0)
local gnm = get_mod(56)
local lk = get_mod(0x2001)

print(string.format("  eboot text=0x%X%08X+0x%X data=0x%X%08X",
    eboot.text_hi, eboot.text_lo, eboot.text_size, eboot.data_hi, eboot.data_lo))
print(string.format("  gnm   text=0x%X%08X+0x%X", gnm.text_hi, gnm.text_lo, gnm.text_size))
print(string.format("  lk    text=0x%X%08X+0x%X", lk.text_hi, lk.text_lo, lk.text_size))

-- ============================================================
-- [B] Scan eboot GOT for GnmDriver + libkernel pointers
-- GOT is typically just before .text end or in .data
-- Scan readable .data region for pointers into gnm/lk text
-- ============================================================
print("")
print("[B] Eboot GOT scan")

local gnm_got = {}
local lk_got = {}
local gnm_text_end = gnm.text_lo + gnm.text_size

-- The real GOT might be at the END of eboot .text (PLT/GOT section)
-- or in the .data section. Try both.
-- First: scan last 64 KB of eboot .text (where PLT stubs live)
local plt_start = eboot.text_base + eboot.text_size - 0x10000
if plt_start < eboot.text_base then plt_start = eboot.text_base end

print("  Scanning eboot .text tail (PLT area)...")
local plt_gnm = 0
local plt_lk = 0
for off = 0, 0x10000 - 8, 8 do
    local v = rq(plt_start + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        if vh == gnm.text_hi and vl >= gnm.text_lo and vl < gnm_text_end then
            plt_gnm = plt_gnm + 1
            if plt_gnm <= 10 then
                table.insert(gnm_got, {addr = plt_start + off, text_off = vl - gnm.text_lo})
            end
        end
        if vh == lk.text_hi and vl >= lk.text_lo and vl < lk.text_lo + lk.text_size then
            plt_lk = plt_lk + 1
        end
    end
end
print(string.format("  PLT area: %d GnmDriver ptrs, %d libkernel ptrs", plt_gnm, plt_lk))

-- Also scan eboot .data (first 256 KB for a bigger game)
print("  Scanning eboot .data (256 KB)...")
local data_gnm = 0
local data_lk = 0
local scan_lim = 0x40000
for off = 0, scan_lim - 8, 8 do
    local v = rq(eboot.data_base + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        if vh == gnm.text_hi and vl >= gnm.text_lo and vl < gnm_text_end then
            data_gnm = data_gnm + 1
            table.insert(gnm_got, {addr = eboot.data_base + off, text_off = vl - gnm.text_lo})
        end
        if vh == lk.text_hi and vl >= lk.text_lo and vl < lk.text_lo + lk.text_size then
            data_lk = data_lk + 1
        end
    end
end
print(string.format("  .data area: %d GnmDriver ptrs, %d libkernel ptrs", data_gnm, data_lk))

-- Print all GnmDriver GOT entries
print("")
print("[C] GnmDriver GOT entries")
for i, g in ipairs(gnm_got) do
    if i > 20 then print("  ... +" .. (#gnm_got - 20) .. " more"); break end
    print(string.format("  GOT@0x%X -> gnm_text+0x%04X", g.addr, g.text_off))
end

-- ============================================================
-- [D] Use sys 674 to find GPU-related VM regions
-- Small RW regions that aren't heap/stack could be MMIO (doorbell)
-- ============================================================
print("")
print("[D] VM map scan for doorbell candidates")

local vm_buf = memory.alloc(0x8000)
local vm_len = memory.alloc(8)
wq(N(vm_len), uint64(0x8000))
local sc_674 = mk(674)
local ok_vm, rv_vm = pcall(function()
    return sc_674(uint64(pid), uint64(vm_buf), uint64(vm_len))
end)
print(string.format("  sys 674 rv=%d", rv_vm and N(rv_vm) or -999))

if ok_vm and rv_vm and N(rv_vm) == 0 then
    local used = rd(N(vm_len))
    if used and used < 0 then used = used + 0x100000000 end
    print(string.format("  returned %d bytes", used or 0))

    -- Each entry is 0x38 bytes: start(8), end(8), offset(8), prot(2), type(2), name(0x20)
    local entry_size = 0x38
    local count = math.floor((used or 0) / entry_size)
    local small_rw = {}

    for i = 0, count - 1 do
        local base = N(vm_buf) + i * entry_size
        local v_start = rq(base)
        local v_end = rq(base + 8)

        if v_start and v_end then
            local sh, sl = get_hi_lo(v_start)
            local eh, el = get_hi_lo(v_end)
            if sh < 0 then sh = sh + 0x100000000 end
            if sl < 0 then sl = sl + 0x100000000 end
            if eh < 0 then eh = eh + 0x100000000 end
            if el < 0 then el = el + 0x100000000 end

            local size_bytes = (eh * 0x100000000 + el) - (sh * 0x100000000 + sl)
            local prot = rd(base + 0x18) or 0
            if prot < 0 then prot = prot + 0x100000000 end
            prot = prot % 0x10000

            -- Read name
            local name = ""
            for j = 0, 0x1F do
                local b = rd(base + 0x1C + j)
                if b then
                    local c = b % 256
                    if c == 0 then break end
                    if c >= 32 and c < 127 then name = name .. string.char(c) end
                end
            end

            -- Small RW regions (< 1 MB, not heap/stack) could be MMIO
            if size_bytes > 0 and size_bytes <= 0x100000 and prot % 4 >= 2 then
                -- prot: bit 0 = read, bit 1 = write
                if name ~= "" and name ~= "heap" and name ~= "stack" then
                    table.insert(small_rw, {
                        start_h = sh, start_l = sl,
                        size = size_bytes, prot = prot, name = name
                    })
                end
            end
        end
    end

    print(string.format("  %d total regions, %d small named RW", count, #small_rw))
    for _, r in ipairs(small_rw) do
        print(string.format("  0x%X%08X size=0x%X prot=0x%X name=%s",
            r.start_h, r.start_l, r.size, r.prot, r.name))
    end

    -- Also print all named regions for context
    print("")
    print("[E] All named regions (first 30)")
    local named_count = 0
    for i = 0, count - 1 do
        local base = N(vm_buf) + i * entry_size
        local name = ""
        for j = 0, 0x1F do
            local b = rd(base + 0x1C + j)
            if b then
                local c = b % 256
                if c == 0 then break end
                if c >= 32 and c < 127 then name = name .. string.char(c) end
            end
        end
        if name ~= "" then
            named_count = named_count + 1
            if named_count <= 30 then
                local v_start = rq(base)
                local v_end = rq(base + 8)
                local sh, sl = get_hi_lo(v_start)
                local eh, el = get_hi_lo(v_end)
                if sh < 0 then sh = sh + 0x100000000 end
                if sl < 0 then sl = sl + 0x100000000 end
                if eh < 0 then eh = eh + 0x100000000 end
                if el < 0 then el = el + 0x100000000 end
                local sz = (eh * 0x100000000 + el) - (sh * 0x100000000 + sl)
                local prot = rd(base + 0x18) or 0
                if prot < 0 then prot = prot + 0x100000000 end
                prot = prot % 0x10000
                print(string.format("  0x%X%08X +0x%X prot=0x%X %s",
                    sh, sl, sz, prot, name))
            end
        end
    end
    if named_count > 30 then print("  ... " .. named_count .. " total named") end
else
    print("  VM map failed — trying alternate entry size")
    -- sys 674 might use different struct size on 14.10
    -- Try printing raw bytes
    for off = 0, 0x80, 4 do
        local d = rd(N(vm_buf) + off)
        if d then
            if d < 0 then d = d + 0x100000000 end
            print(string.format("  [+0x%02X] 0x%08X", off, d))
        end
    end
end

print("")
print("=== 530i DONE ===")
