-- CRASH_CLASS: MODERATE
-- PROBE 50g: sys 665/668 under SIGSYS ignore
--
-- 665 and 668 kill on zeros. With SIGSYS ignored, nosys calls return -1.
-- If 665/668 are nosys, they'll return -1 under SIG_IGN.
-- If they're real handlers that fault, they'll still kill.
-- Also test 661 (known nosys per 353a) as control.

print("=== PROBE 50g: 665/668 SIGSYS CLASSIFY ===")
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Install SIG_IGN for SIGSYS (signal 12)
print("[SETUP] sigaction(12, SIG_IGN)")
local sa = memory.alloc(0x40)
for i = 0, 0x3F, 4 do wd(N(sa) + i, 0) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local ok_sa, rv_sa = pcall(function()
    return mk(416)(uint64(12), sa, uint64(0))
end)
print("  sigaction ret=" .. (ok_sa and tostring(N(rv_sa)) or "PFAIL"))
if not alive() then print("DIED on sigaction!") return end

-- [A] Control: sys 661 (known nosys from 353a)
print("")
print("[A] sys 661 (known nosys)")
local ok661, rv661 = pcall(function()
    return mk(661)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("  661(zeros) -> " .. (ok661 and tostring(N(rv661)) or "PFAIL"))
if not alive() then print("  DIED! (unexpected for nosys under SIG_IGN)") return end

-- [B] sys 665 with zeros
print("")
print("[B] sys 665")
local ok665, rv665 = pcall(function()
    return mk(665)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if not alive() then
    print("  665(zeros) -> KILLED (real handler, faults on bad args)")
    return
end
print("  665(zeros) -> " .. (ok665 and tostring(N(rv665)) or "PFAIL"))

-- If alive, try 665 with a valid-looking argument (pointer to buffer)
local buf = memory.alloc(0x1000)
local BUF = N(buf)
for i = 0, 0xFF, 4 do wd(BUF + i, 0) end

-- From the AIO range docs: 665 might be aio_suspend (needs aiocb pointer)
-- Try with a pointer arg
local ok665b, rv665b = pcall(function()
    return mk(665)(buf, uint64(1), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if not alive() then
    print("  665(buf,1) -> KILLED")
    return
end
print("  665(buf,1) -> " .. (ok665b and tostring(N(rv665b)) or "PFAIL"))

-- [C] sys 668 with zeros
print("")
print("[C] sys 668")
local ok668, rv668 = pcall(function()
    return mk(668)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if not alive() then
    print("  668(zeros) -> KILLED (real handler, faults on bad args)")
    return
end
print("  668(zeros) -> " .. (ok668 and tostring(N(rv668)) or "PFAIL"))

-- If alive, try with pointer arg
local ok668b, rv668b = pcall(function()
    return mk(668)(buf, uint64(1), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if not alive() then
    print("  668(buf,1) -> KILLED")
    return
end
print("  668(buf,1) -> " .. (ok668b and tostring(N(rv668b)) or "PFAIL"))

-- [D] Also quickly test sendfile(393) with valid fd
print("")
print("[D] sendfile with socket fd")
local sc_socket = mk(97)
local ok_sock, sock = pcall(function()
    return sc_socket(uint64(2), uint64(1), uint64(6))
end)
sock = ok_sock and N(sock) or -999
if sock >= 0 then
    local ok_sf, rv_sf = pcall(function()
        return mk(393)(uint64(sock), uint64(0), uint64(0), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)
    print("  sendfile(sock, 0, 0, 0) -> " .. (ok_sf and tostring(N(rv_sf)) or "PFAIL"))
    pcall(function() mk(6)(uint64(sock)) end)
else
    print("  no TCP socket")
end
if not alive() then print("DIED!") return end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 50g COMPLETE ===")
