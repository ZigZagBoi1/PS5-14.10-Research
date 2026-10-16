-- CRASH_CLASS: SAFE (read-only code dump)
-- PROBE 42h: Dump fn_addr target code using byte reads
-- Also dump libkernel entry, dlsym with all module handles

print("=== PROBE 42h: CODE DUMP ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Dump bytes at an address using dword reads (more reliable than qword)
local function dump_dwords(label, base_addr, count)
    print(label .. ":")
    local line = ""
    local any = false
    for i = 0, count - 1 do
        local d = safe_rd(base_addr + i * 4)
        if d then
            line = line .. string.format("%08X ", d)
            any = true
            if (i + 1) % 4 == 0 then
                print(string.format("  +%03X: %s", (i - 3) * 4, line))
                line = ""
            end
        else
            if not any then print("  NOT READABLE") end
            break
        end
    end
    if #line > 0 then print("  +" .. line) end
    return any
end

local sc_getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(588)
local sc_dgl = make_syscall(592)
local sc_dgi = make_syscall(593)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) Get fn_addr value
--------------------------------------------------------------------
print("")
print("=== A: FN_ADDR ===")
local pipe_str = tostring(syscall.pipe)
local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
print("fn_addr ptr: " .. (fn_addr_str or "nil"))

-- GPU mmap for heap access
local gpu_size = 512 * 0x4000
local gpu_addr
pcall(function()
    gpu_addr = sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

local fn_val_h, fn_val_l = 0, 0
if fn_addr_str and gpu_addr then
    local fn_ptr = uint64(fn_addr_str)
    local fn_lo = safe_rd(fn_ptr)
    local fn_hi = safe_rd(fn_ptr + 4)
    fn_val_l = fn_lo or 0
    fn_val_h = fn_hi or 0
    print(string.format("fn_addr value: %08X_%08X", fn_val_h, fn_val_l))
end

--------------------------------------------------------------------
-- B) Read code at fn_addr target using dword reads
--------------------------------------------------------------------
print("")
print("=== B: CODE AT FN_ADDR TARGET ===")
if fn_val_h > 0 or fn_val_l > 0 then
    local target = uint64(string.format("0x%X%08X", fn_val_h, fn_val_l))
    local ok = dump_dwords("fn_addr target code", target, 32)

    -- Also scan for kernel-range dwords in the code
    if ok then
        print("  scanning for kernel refs:")
        for i = 0, 63 do
            local d = safe_rd(target + i * 4)
            if not d then break end
            -- Check pairs of dwords for kernel addresses
            if i % 2 == 0 then
                local d2 = safe_rd(target + i * 4 + 4)
                if d2 and d2 >= 0xFFFF8000 then
                    print(string.format("    +%03X: %08X_%08X KPTR!", i * 4, d2, d))
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- C) Get libkernel base and dump entry
--------------------------------------------------------------------
print("")
print("=== C: LIBKERNEL ===")
do
    local handles = memory.alloc(256)
    local num_buf = memory.alloc(8)
    pcall(function() sc_dgl(handles, 64, num_buf) end)
    local num = safe_rd(num_buf) or 0

    local info = memory.alloc(0x200)
    local libk_text_h, libk_text_l = 0, 0
    local libk_handle = 0

    for i = 0, math.min(num-1, 39) do
        local h = safe_rd(handles + i * 4)
        if h and h > 0 then
            for j = 0, 0x1F, 4 do safe_wd(info+j, 0) end
            safe_wd(info, 0x160)
            pcall(function() sc_dgi(uint64(h), info) end)
            local b = safe_rd(info + 8)
            if b then
                b = b % 256
                if b == string.byte("l") then  -- starts with 'l'
                    local name = ""
                    for j = 0, 19 do
                        local c = safe_rd(info + 8 + j)
                        if c then c = c % 256
                            if c >= 0x20 and c < 0x7F then name = name .. string.char(c)
                            elseif c == 0 then break end
                        end
                    end
                    if name:find("libkernel") then
                        libk_handle = h
                        libk_text_l = safe_rd(info + 0x108) or 0
                        libk_text_h = safe_rd(info + 0x10C) or 0
                        break
                    end
                end
            end
        end
    end

    if libk_text_h > 0 or libk_text_l > 0 then
        print(string.format("libkernel: h=%d text=%08X_%08X", libk_handle, libk_text_h, libk_text_l))

        -- Check if fn_addr is within libkernel
        if fn_val_h == libk_text_h then
            local off = fn_val_l - libk_text_l
            print(string.format("fn_addr = libkernel + 0x%X", off))
        else
            print("fn_addr NOT in libkernel text segment")
            print(string.format("  fn_addr: %08X_%08X", fn_val_h, fn_val_l))
            print(string.format("  libk:    %08X_%08X", libk_text_h, libk_text_l))
        end
    end
end

--------------------------------------------------------------------
-- D) Dlsym with each module handle
--------------------------------------------------------------------
print("")
print("=== D: DLSYM ===")
do
    local sc_dlsym = make_syscall(594)
    local handles = memory.alloc(256)
    local num_buf = memory.alloc(8)
    pcall(function() sc_dgl(handles, 64, num_buf) end)
    local num = safe_rd(num_buf) or 0

    local sym_name = memory.alloc(64)
    local addr_out = memory.alloc(8)

    -- Write "getpid" as symbol name
    local sym = "getpid"
    for i = 1, #sym do memory.write_byte(sym_name+(i-1), string.byte(sym, i)) end
    memory.write_byte(sym_name + #sym, 0)

    -- Try handles 0, 1, 2, and actual module handles
    local try_handles = {0, 1, 2}
    for i = 0, math.min(num-1, 10) do
        local h = safe_rd(handles + i * 4)
        if h then try_handles[#try_handles+1] = h end
    end

    for _, h in ipairs(try_handles) do
        safe_wd(addr_out, 0)
        safe_wd(addr_out+4, 0)
        local ok, ret = pcall(function()
            return sc_dlsym(uint64(h), uint64(sym_name), uint64(addr_out))
        end)
        local rv = ok and to_num(ret) or -999
        if rv == 0 then
            local al = safe_rd(addr_out) or 0
            local ah = safe_rd(addr_out+4) or 0
            print(string.format("  h=%d: getpid = %08X_%08X", h, ah, al))
        else
            -- Only print a few
            if h <= 2 or h == try_handles[4] then
                print(string.format("  h=%d: ret=%d", h, rv))
            end
        end
    end
end

-- Cleanup
if gpu_addr then pcall(function() sc_munmap(gpu_addr, uint64(gpu_size)) end) end

print("")
print("=== PROBE 42h COMPLETE ===")
