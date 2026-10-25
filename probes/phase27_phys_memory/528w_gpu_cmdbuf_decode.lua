-- CRASH_CLASS: LOW
-- PROBE 528w: Decode GPU command buffer at dmem0 offset 0
--
-- dmem0 offset 0 contains AMD PM4 packets. Decode them to understand:
-- 1. What opcodes are being used
-- 2. Whether there are any DMA/COPY commands
-- 3. What physical addresses the GPU is accessing
-- 4. The ring buffer structure
--
-- PM4 type-3 packet format:
--   Header dword: [31:30]=type(3), [29:16]=count-1, [15:8]=opcode, [7:0]=predicate
--   So 0xC00176xx → type=3, count=0, opcode=0x01, predicate=0x76xx? No...
--   Actually: bits [31:30]=11 (type 3), [29:16]=size-2 in dwords,
--   [15:8]=opcode, [7:0]=various
--
-- Wait, AMD PM4 is different. Let me dump raw and decode.
-- Type 0: [31:30]=00, [29:16]=base_index, [15:0]=count
-- Type 2: [31:30]=10, filler
-- Type 3: [31:30]=11, [29:16]=count-1, [15:8]=opcode, [7:0]=predicate/shader
--
-- But the values we see (0xC0012800, 0xC0017600, 0xC0016900) have:
-- - 0xC001xxxx → bits [31:30]=11, [29:16]=0x0001 → count=2 (1+1)
-- These look like GFX type-3 packets.

print("=== PROBE 528w: GPU CMD BUFFER DECODE ===")
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

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local sc_477 = mk(477)
local sc_73 = mk(73)
local PAGE = 0x4000

local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
print("fd=" .. fd)

-- Map first 16 pages (256 KB) of dmem0
local map_size = 16 * PAGE
local ok_m, rv_m = pcall(function()
    return sc_477(uint64(0), uint64(map_size), uint64(1), uint64(1), uint64(fd), uint64(0))
end)
if not ok_m or not rv_m then print("FAIL"); return end
local rh, rl = get_hi_lo(rv_m)
if rh < 0 then rh = rh + 0x100000000 end
if rh == 0xFFFFFFFF then print("FAIL -1"); return end
local va = N(rv_m)

-- Known PM4 opcodes (from amdgpu/mesa headers)
local pm4_ops = {
    [0x10] = "NOP",
    [0x11] = "SET_BASE",
    [0x12] = "CLEAR_STATE",
    [0x15] = "DISPATCH_DIRECT",
    [0x16] = "DISPATCH_INDIRECT",
    [0x20] = "ATOMIC_GDS",
    [0x21] = "ATOMIC_MEM",
    [0x22] = "OCCLUSION_QUERY",
    [0x27] = "SET_PREDICATION",
    [0x28] = "REG_RMW",
    [0x2D] = "COND_EXEC",
    [0x2E] = "PRED_EXEC",
    [0x30] = "DRAW_INDIRECT",
    [0x33] = "DRAW_INDEX_INDIRECT",
    [0x34] = "INDEX_BASE",
    [0x36] = "INDEX_TYPE",
    [0x38] = "DRAW_INDIRECT_MULTI",
    [0x40] = "COPY_DATA",
    [0x41] = "CP_DMA",
    [0x43] = "PFP_SYNC_ME",
    [0x46] = "EVENT_WRITE",
    [0x47] = "EVENT_WRITE_EOP",
    [0x48] = "EVENT_WRITE_EOS",
    [0x49] = "RELEASE_MEM",
    [0x50] = "DMA_DATA",
    [0x58] = "CONTEXT_REG_RMW",
    [0x68] = "SET_CONFIG_REG",
    [0x69] = "SET_CONTEXT_REG",
    [0x76] = "SET_SH_REG",
    [0x79] = "SET_UCONFIG_REG",
    [0x80] = "LOAD_SH_REG",
    [0x81] = "LOAD_SH_REG_INDEX",
    [0xA0] = "LOAD_CONTEXT_REG",
    [0xA1] = "LOAD_CONTEXT_REG_INDEX",
}

-- Decode PM4 packets from the command buffer
print("")
print("[A] PM4 packet decode (first 2KB)")

local pos = 0
local pkt_count = 0
local max_decode = 2048  -- bytes

while pos < max_decode do
    local hdr = rd(va + pos)
    if hdr == nil or hdr == 0 then break end
    if hdr < 0 then hdr = hdr + 0x100000000 end

    local pkt_type = math.floor(hdr / 0x40000000) % 4
    pkt_count = pkt_count + 1

    if pkt_type == 3 then
        local count = math.floor(hdr / 0x10000) % 0x4000 + 1  -- bits [29:16] + 1 = dwords following
        local opcode = math.floor(hdr / 0x100) % 0x100         -- bits [15:8]
        local pred = hdr % 0x100                                -- bits [7:0]

        local opname = pm4_ops[opcode] or string.format("UNK_0x%02X", opcode)

        -- Print packet info
        local line = string.format("  [0x%03X] T3 op=0x%02X(%s) count=%d",
            pos, opcode, opname, count)

        -- For key opcodes, print the payload
        if opcode == 0x40 then  -- COPY_DATA
            line = line .. " ***"
            -- COPY_DATA: src_sel, dst_sel, src_addr_lo, src_addr_hi, dst_addr_lo, dst_addr_hi
        elseif opcode == 0x41 then  -- CP_DMA
            line = line .. " *** DMA ***"
        elseif opcode == 0x50 then  -- DMA_DATA
            line = line .. " *** DMA_DATA ***"
        end

        print(line)

        -- Print payload for interesting opcodes
        if opcode == 0x40 or opcode == 0x41 or opcode == 0x50 or opcode == 0x49 then
            for d = 1, math.min(count, 8) do
                local payload = rd(va + pos + d * 4)
                if payload then
                    if payload < 0 then payload = payload + 0x100000000 end
                    print(string.format("    [+%d] 0x%08X", d, payload))
                end
            end
        end

        pos = pos + (count + 1) * 4  -- header + count dwords
    elseif pkt_type == 2 then
        -- Type 2: NOP filler
        pos = pos + 4
    elseif pkt_type == 0 then
        -- Type 0: register write
        local count = hdr % 0x10000 + 1
        local base = math.floor(hdr / 0x10000) % 0x4000
        print(string.format("  [0x%03X] T0 base=0x%04X count=%d", pos, base, count))
        pos = pos + (count + 1) * 4
    else
        -- Unknown
        print(string.format("  [0x%03X] T%d hdr=0x%08X", pos, pkt_type, hdr))
        pos = pos + 4
    end

    if pkt_count > 200 then print("  ... (truncated)"); break end
end

print("")
print("  total packets: " .. pkt_count)

-- ============================================================
-- [B] Find all COPY_DATA / DMA_DATA / CP_DMA in the full 256KB
-- ============================================================
print("")
print("[B] Scan full 256KB for DMA opcodes")

local dma_hits = {}
for off = 0, map_size - 4, 4 do
    local d = rd(va + off)
    if d then
        if d < 0 then d = d + 0x100000000 end
        local pt = math.floor(d / 0x40000000) % 4
        if pt == 3 then
            local op = math.floor(d / 0x100) % 0x100
            if op == 0x40 or op == 0x41 or op == 0x50 then
                local count = math.floor(d / 0x10000) % 0x4000 + 1
                table.insert(dma_hits, {off, op, count})
            end
        end
    end
end

print("  DMA/COPY opcodes found: " .. #dma_hits)
for _, h in ipairs(dma_hits) do
    local opname = pm4_ops[h[2]] or "?"
    print(string.format("    off=0x%X op=0x%02X(%s) count=%d", h[1], h[2], opname, h[3]))
    -- Dump payload
    for d = 1, math.min(h[3], 8) do
        local payload = rd(va + h[1] + d * 4)
        if payload then
            if payload < 0 then payload = payload + 0x100000000 end
            print(string.format("      [+%d] 0x%08X", d, payload))
        end
    end
end

-- ============================================================
-- [C] Opcode histogram
-- ============================================================
print("")
print("[C] Opcode histogram")
local hist = {}
for off = 0, map_size - 4, 4 do
    local d = rd(va + off)
    if d then
        if d < 0 then d = d + 0x100000000 end
        local pt = math.floor(d / 0x40000000) % 4
        if pt == 3 then
            local op = math.floor(d / 0x100) % 0x100
            hist[op] = (hist[op] or 0) + 1
        end
    end
end
-- Sort by count
local sorted = {}
for op, cnt in pairs(hist) do table.insert(sorted, {op, cnt}) end
table.sort(sorted, function(a, b) return a[2] > b[2] end)
for i, e in ipairs(sorted) do
    if i > 20 then break end
    local name = pm4_ops[e[1]] or "?"
    print(string.format("  0x%02X (%s): %d", e[1], name, e[2]))
end

pcall(function() sc_73(rv_m, uint64(map_size)) end)
pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
print("")
print("=== 528w DONE ===")
