-- CRASH_CLASS: MODERATE
-- PROBE 544c: MapDirectMemory 7-arg with full diagnostics
--
-- 544b hung/crashed — need to verify resume_addr calculation.
-- This probe measures actual chain offsets at each step.

print("=== PROBE 544c: MapDM 7-ARG DIAGNOSTIC ===")
io.stdout:setvbuf("no")

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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end

if not libkernel_base then print("FATAL: no libkernel_base"); return end
print("libkernel=" .. q(libkernel_base))
print("pid=" .. to_num(syscall.getpid()))

local map_fn = libkernel_base + uint64(0x15020)

-- [A] Measure chain operation sizes precisely
print("")
print("[A] Measure chain op sizes")
local test_chain = ropchain({ stack_size = 0x4000 })
local rsp0 = test_chain:get_rsp()

-- Measure push_write_qword_memory
local rsp_before_write = test_chain:get_rsp()
test_chain:push_write_qword_memory(uint64(0x1000), 0x2000)
local rsp_after_write = test_chain:get_rsp()
local write_size = to_num(rsp_after_write) - to_num(rsp_before_write)
print("  push_write_qword_memory: " .. write_size .. " bytes (" .. (write_size/8) .. " slots)")

-- Measure push_set_rsp
local rsp_before_pivot = test_chain:get_rsp()
test_chain:push_set_rsp(uint64(0x3000))
local rsp_after_pivot = test_chain:get_rsp()
local pivot_size = to_num(rsp_after_pivot) - to_num(rsp_before_pivot)
print("  push_set_rsp: " .. pivot_size .. " bytes (" .. (pivot_size/8) .. " slots)")

-- Measure push_sysv with 6 args
local test_chain2 = ropchain({ stack_size = 0x4000 })
local rsp_before_sysv = test_chain2:get_rsp()
test_chain2:push_sysv(uint64(1), uint64(2), uint64(3), uint64(4), uint64(5), uint64(6))
local rsp_after_sysv = test_chain2:get_rsp()
local sysv_size = to_num(rsp_after_sysv) - to_num(rsp_before_sysv)
print("  push_sysv(6 args): " .. sysv_size .. " bytes (" .. (sysv_size/8) .. " slots)")

-- Measure individual register sets
local test_chain3 = ropchain({ stack_size = 0x4000 })

local rsp_b = test_chain3:get_rsp()
test_chain3:push_set_rdi(uint64(1))
print("  push_set_rdi: " .. (to_num(test_chain3:get_rsp()) - to_num(rsp_b)) .. " bytes")

rsp_b = test_chain3:get_rsp()
test_chain3:push_set_rsi(uint64(2))
print("  push_set_rsi: " .. (to_num(test_chain3:get_rsp()) - to_num(rsp_b)) .. " bytes")

rsp_b = test_chain3:get_rsp()
test_chain3:push_set_rdx(uint64(3))
print("  push_set_rdx: " .. (to_num(test_chain3:get_rsp()) - to_num(rsp_b)) .. " bytes")

rsp_b = test_chain3:get_rsp()
test_chain3:push_set_rcx(uint64(4))
print("  push_set_rcx: " .. (to_num(test_chain3:get_rsp()) - to_num(rsp_b)) .. " bytes")

rsp_b = test_chain3:get_rsp()
test_chain3:push_set_r8(uint64(5))
print("  push_set_r8: " .. (to_num(test_chain3:get_rsp()) - to_num(rsp_b)) .. " bytes")

rsp_b = test_chain3:get_rsp()
test_chain3:push_set_r9(uint64(6))
print("  push_set_r9: " .. (to_num(test_chain3:get_rsp()) - to_num(rsp_b)) .. " bytes")

-- Measure push_store_retval
rsp_b = test_chain3:get_rsp()
test_chain3:push_store_retval()
print("  push_store_retval: " .. (to_num(test_chain3:get_rsp()) - to_num(rsp_b)) .. " bytes")

-- [B] Build real chain with precise measurements
print("")
print("[B] Build real chain")

-- Use dmem0 fallback for phys
local phys_addr = uint64("0x110000000")
print("  phys=" .. q(phys_addr))

local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))
local custom_stub = memory.alloc(0x100)
for off = 0, 0xFC, 4 do wd(custom_stub + off, 0) end

local chain = ropchain({
    fcall_stub_padding_size = 0x50000,
    stack_size = 0x8000
})

-- Track RSP at each step
local rsp_log = {}
local function log_rsp(label)
    local v = chain:get_rsp()
    rsp_log[#rsp_log+1] = {label=label, rsp=v}
    print("  " .. label .. " rsp=" .. q(v))
end

log_rsp("start")

-- Write stub slots 0-3 (slot 4 written later when we know resume addr)
chain:push_write_qword_memory(custom_stub + uint64(0x00), map_fn)
log_rsp("after stub[0]")

chain:push_write_qword_memory(custom_stub + uint64(0x08), gadgets["pop rbx; ret"])
log_rsp("after stub[1]")

chain:push_write_qword_memory(custom_stub + uint64(0x10), 0)
log_rsp("after stub[2]")

chain:push_write_qword_memory(custom_stub + uint64(0x18), gadgets["pop rsp; ret"])
log_rsp("after stub[3]")

-- Set up 6 register args
chain:push_sysv(
    uint64(virt_out),      -- rdi
    uint64(0x4000),        -- rsi
    uint64(3),             -- rdx
    uint64(0),             -- rcx
    phys_addr,             -- r8
    uint64(0x4000)         -- r9
)
log_rsp("after push_sysv")

-- Now: write resume addr + pivot
-- resume = current_rsp + write_size + pivot_size
local actual_resume_offset = write_size + pivot_size
local resume_addr = chain:get_rsp() + uint64(actual_resume_offset)
print("  resume_offset=" .. actual_resume_offset .. " resume=" .. q(resume_addr))

chain:push_write_qword_memory(custom_stub + uint64(0x20), resume_addr)
log_rsp("after stub[4]")

chain:push_set_rsp(custom_stub)
log_rsp("after pivot (should match resume)")

-- RESUME POINT
chain:push_store_retval()
log_rsp("after store_retval")

-- Verify resume addr matches
print("  expected resume=" .. q(resume_addr))
print("  actual resume point=" .. q(rsp_log[#rsp_log-1].rsp))
local match = (to_num(resume_addr) == to_num(rsp_log[#rsp_log-1].rsp))
print("  MATCH=" .. tostring(match))

if not match then
    print("  *** RESUME ADDR MISMATCH — WOULD CRASH ***")
    print("  diff=" .. (to_num(rsp_log[#rsp_log-1].rsp) - to_num(resume_addr)))
    print("  ABORT — fix the offset calculation")
    print("canary: ok=" .. tostring(pcall(function() return syscall.getpid() end)))
    print("=== 544c DONE (ABORTED) ===")
    return
end

-- [C] Execute
print("")
print("[C] execute")
local ok_mt, map_thr = pcall(function() return thread:new(chain) end)
if not ok_mt then print("  thread:new FAIL: " .. tostring(map_thr)); return end

print("  running...")
local ok_mr, err_mr = pcall(function() map_thr:run(true) end)
print("  run ok=" .. tostring(ok_mr) .. " err=" .. tostring(err_mr))

if ok_mr then
    print("  joining...")
    local ok_mj, err_mj = pcall(function() map_thr:join() end)
    print("  join ok=" .. tostring(ok_mj) .. " err=" .. tostring(err_mj))

    local map_rv = rq(chain:get_last_retval_addr())
    local virt_addr = rq(virt_out)
    print("  map_rv=" .. q(map_rv) .. " (0=success)")
    print("  virt_addr=" .. q(virt_addr))

    -- Dump stub after execution
    print("  stub after:")
    for off = 0, 0x28, 8 do
        local v = rq(custom_stub + uint64(off))
        print(string.format("    [+0x%02X] %s", off, v and q(v) or "FAULT"))
    end

    if map_rv and to_num(map_rv) == 0 and virt_addr and to_num(virt_addr) ~= 0 then
        print("  *** MapDirectMemory SUCCEEDED ***")
        local ok_w = pcall(function() memory.write_dword(virt_addr, 0xDEADBEEF) end)
        local rb = rd(to_num(virt_addr))
        if rb then
            if rb < 0 then rb = rb + 0x100000000 end
            print(string.format("  R/W test: wrote 0xDEADBEEF read 0x%08X", rb))
        end
    else
        print("  MapDM FAILED")
        if map_rv then
            local n = to_num(map_rv); if n < 0 then n = n + 0x100000000 end
            print(string.format("  rv=0x%X", n))
        end
    end
else
    print("  thread crashed")
end

print("")
print("canary: ok=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== 544c DONE ===")
