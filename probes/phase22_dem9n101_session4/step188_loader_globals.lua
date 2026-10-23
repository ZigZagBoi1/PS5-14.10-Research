-- step188: Use loader globals + SROP for syscalls 592/593
print("=== STEP188 ===")

local function tn(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function rq(a) return memory.read_qword(a) end
local function wq(a, v) memory.write_qword(a, v) end
local function rd(a) return memory.read_dword(a) end
local function wd(a, v) memory.write_dword(a, v) end
local function wb(a, v) memory.write_byte(a, v) end
local Z = uint64(0)

-- T1: Dump loader globals
print("---T1: loader globals---")
pcall(function()
    -- Known globals from the framework
    if eboot_addrofs then
        print("eboot_addrofs keys:")
        for k, v in pairs(eboot_addrofs) do
            print("  " .. k .. "=" .. tostring(v))
        end
    else
        print("eboot_addrofs=nil")
    end

    if libc_addrofs then
        print("libc_addrofs keys:")
        for k, v in pairs(libc_addrofs) do
            print("  " .. k .. "=" .. tostring(v))
        end
    else
        print("libc_addrofs=nil")
    end

    -- Check for base addresses
    if eboot_base then print("eboot_base=" .. tostring(eboot_base)) else print("eboot_base=nil") end
    if libc_base then print("libc_base=" .. tostring(libc_base)) else print("libc_base=nil") end
    if libkernel_base then print("libkernel_base=" .. tostring(libkernel_base)) else print("libkernel_base=nil") end
end)

-- T2: Check syscall table for Sony-specific entries
print("---T2: syscall details---")
pcall(function()
    print("syscall.syscall_address=" .. tostring(syscall.syscall_address))
    -- Check pre-resolved Sony syscalls
    if syscall.dlsym then print("dlsym=" .. tostring(syscall.dlsym)) else print("dlsym=nil") end
    if syscall.dynlib_load_prx then print("load_prx=" .. tostring(syscall.dynlib_load_prx)) else print("load_prx=nil") end
    if syscall.is_in_sandbox then print("is_in_sandbox=" .. tostring(syscall.is_in_sandbox)) else print("is_in_sandbox=nil") end

    -- Try calling is_in_sandbox
    local ok, rv = pcall(function()
        return syscall.is_in_sandbox(Z, Z, Z, Z, Z, Z)
    end)
    print("sandbox_rv=" .. tostring(ok) .. " " .. tostring(rv))
end)

-- T3: Try SROP approach to call syscall 592
print("---T3: SROP for syscall 592---")
pcall(function()
    -- SROP (sigreturn 417) crafts a ucontext that calls any syscall
    -- MC offsets: RDI=+0x08, RSI=+0x10, RDX=+0x18, RCX=+0x20
    --             R8=+0x28, R9=+0x30, RAX=+0x38
    --             RIP=+0xA0, RSP=+0xB8, FLAGS=+0xC0

    -- We need: RAX=592, RDI=id_buf, RSI=cnt_buf, RDX=0
    -- RIP = syscall_address (the syscall;ret gadget)
    -- RSP = return stack

    local sc_addr = syscall.syscall_address
    print("sc_addr=" .. tostring(sc_addr))

    local id_buf = memory.alloc(0x400)
    local cnt_buf = memory.alloc(8)
    wq(cnt_buf, uint64(0x40))

    -- Return stack for after sigreturn
    local ret_stack = memory.alloc(0x1000)
    -- The return from syscall needs to go somewhere safe
    -- After SROP syscall;ret, execution goes to the return address on stack
    -- We need RIP after the syscall to return to normal execution
    -- This is complex; let me use a simpler approach first

    -- Actually, let's check if the loader has a "call_syscall" or similar function
    -- that was used to implement make_syscall in prior sessions
end)

-- T4: Check what native_invoke can do
print("---T4: native_invoke---")
pcall(function()
    if native_invoke then
        print("native_invoke type=" .. type(native_invoke))
    else
        print("native_invoke=nil")
    end
    if native then
        print("native type=" .. type(native))
        if type(native) == "table" then
            for k, v in pairs(native) do
                print("  " .. k .. "=" .. type(v))
            end
        end
    else
        print("native=nil")
    end
end)

-- T5: Try fcall to call known libc functions
print("---T5: fcall identification---")
pcall(function()
    print("fcall type=" .. type(fcall))

    -- fcall usage: fcall(address) creates a callable wrapper
    -- libc_addrofs has addresses of libc functions

    if not libc_addrofs then print("no libc_addrofs") return end

    -- Try getpid via fcall to verify it works
    if libc_addrofs.getpid then
        local ok, rv = pcall(function()
            return fcall(libc_addrofs.getpid)()
        end)
        print("getpid via fcall: ok=" .. tostring(ok) .. " rv=" .. tostring(rv))
    end

    -- Try sceKernelDlsym if available
    if libc_addrofs.sceKernelDlsym then
        print("sceKernelDlsym addr=" .. tostring(libc_addrofs.sceKernelDlsym))
    end

    -- Try to find dynlib_get_list / dynlib_get_info in libc_addrofs
    for k, v in pairs(libc_addrofs) do
        if k:find("dynlib") or k:find("module") or k:find("dlsym") or
           k:find("Kernel") or k:find("kernel") then
            print("  " .. k .. "=" .. tostring(v))
        end
    end
end)

-- T6: Use vmmap sysctl to find GOT region
print("---T6: vmmap sysctl for GOT---")
pcall(function()
    syscall.resolve({ sysctl = 202, getpid = 20 })

    local pid = tn(syscall.getpid())
    print("pid=" .. pid)

    -- MIB: {1, 14, 32, pid} for KERN_PROC_VMMAP
    local mib = memory.alloc(0x20)
    wd(mib, 1)      -- CTL_KERN
    wd(mib + 4, 14)  -- KERN_PROC
    wd(mib + 8, 32)  -- KERN_PROC_VMMAP
    wd(mib + 12, pid)

    -- First call to get size
    local oldsz = memory.alloc(8)
    wq(oldsz, Z)

    local rv = syscall.sysctl(mib, uint64(4), Z, oldsz, Z, Z)
    local sz = tn(rq(oldsz))
    print("vmmap size=" .. sz)

    if sz > 0 and sz < 0x100000 then
        local buf = memory.alloc(sz + 0x1000)
        wq(oldsz, uint64(sz + 0x1000))
        local rv2 = syscall.sysctl(mib, uint64(4), buf, oldsz, Z, Z)
        local actual = tn(rq(oldsz))
        print("vmmap actual=" .. actual .. " rv=" .. tostring(rv2))

        if tn(rv2) == 0 and actual > 0 then
            -- Parse kinfo_vmentry entries
            local off = 0
            local entry_count = 0
            while off < actual do
                local struct_sz = tn(rd(buf + off))
                if struct_sz == 0 or struct_sz > 0x1000 then break end

                local kve_start = rq(buf + off + 8)
                local kve_end = rq(buf + off + 16)
                local kve_prot = tn(rd(buf + off + 56))  -- protection

                -- Read path at +112
                local path = ""
                for i = 0, 63 do
                    local b = tn(memory.read_byte(buf + off + 112 + i))
                    if b == 0 then break end
                    if b >= 32 and b < 127 then path = path .. string.char(b) end
                end

                local size_kb = (tn(kve_end) - tn(kve_start)) / 1024
                local prot_str = ""
                if kve_prot % 2 >= 1 then prot_str = prot_str .. "r" else prot_str = prot_str .. "-" end
                if math.floor(kve_prot / 2) % 2 >= 1 then prot_str = prot_str .. "w" else prot_str = prot_str .. "-" end
                if math.floor(kve_prot / 4) % 2 >= 1 then prot_str = prot_str .. "x" else prot_str = prot_str .. "-" end

                -- Only print interesting regions (not the huge heap)
                if size_kb < 100000 and tn(kve_start) > 0 then
                    print(string.format("  %s-%s %5dK %s %s",
                        tostring(kve_start), tostring(kve_end),
                        size_kb, prot_str, path))
                end

                entry_count = entry_count + 1
                off = off + struct_sz
            end
            print("entries=" .. entry_count)
        end
    end
end)

print("=== STEP188_DONE ===")
