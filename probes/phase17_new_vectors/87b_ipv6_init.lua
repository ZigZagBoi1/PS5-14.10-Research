-- CRASH_CLASS: LOW
-- PROBE 87b: Explore IPv6 kernel R/W initialization path
-- ipv6_kernel_rw has init, create_pipe_pair, create_overlapped_ipv6_sockets
-- Check what each needs and if we can partially initialize

print("=== PROBE 87b ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

print("pid=" .. to_num(syscall.getpid()))

-- Step 1: Dump ipv6_kernel_rw.data
print("--- IPV6 DATA ---")
local count = 0
for k, v in pairs(ipv6_kernel_rw.data) do
    count = count + 1
    print(tostring(k) .. "=" .. type(v) .. " " .. tostring(v))
end
print("count=" .. count)

-- Step 2: Bytecode of create_pipe_pair
print("")
print("--- CREATE_PIPE_PAIR ---")
local ok1, bc1 = pcall(string.dump, ipv6_kernel_rw.create_pipe_pair)
if ok1 then
    local strs = {}
    for s in bc1:gmatch("[%a_][%w_%.]+") do
        if #s > 2 and not strs[s] then
            strs[s] = true
            print("  " .. s)
        end
    end
end

-- Step 3: Bytecode of init
print("")
print("--- INIT ---")
local ok2, bc2 = pcall(string.dump, ipv6_kernel_rw.init)
if ok2 then
    local strs = {}
    for s in bc2:gmatch("[%a_][%w_%.]+") do
        if #s > 2 and not strs[s] then
            strs[s] = true
            print("  " .. s)
        end
    end
end

-- Step 4: Bytecode of create_overlapped_ipv6_sockets
print("")
print("--- CREATE_OVERLAPPED ---")
local ok3, bc3 = pcall(string.dump, ipv6_kernel_rw.create_overlapped_ipv6_sockets)
if ok3 then
    local strs = {}
    for s in bc3:gmatch("[%a_][%w_%.]+") do
        if #s > 2 and not strs[s] then
            strs[s] = true
            print("  " .. s)
        end
    end
end

-- Step 5: Bytecode of get_fd_data_addr
print("")
print("--- GET_FD_DATA_ADDR ---")
local ok4, bc4 = pcall(string.dump, ipv6_kernel_rw.get_fd_data_addr)
if ok4 then
    local strs = {}
    for s in bc4:gmatch("[%a_][%w_%.]+") do
        if #s > 2 and not strs[s] then
            strs[s] = true
            print("  " .. s)
        end
    end
end

-- Step 6: Try create_pipe_pair (it probably just creates a pipe)
print("")
print("--- TRY CREATE_PIPE_PAIR ---")
local ok5, r5 = pcall(ipv6_kernel_rw.create_pipe_pair)
print("ok=" .. tostring(ok5))
if ok5 then
    print("result=" .. type(r5) .. " " .. tostring(r5))
    if type(r5) == "table" then
        for k, v in pairs(r5) do print("  " .. tostring(k) .. "=" .. tostring(v)) end
    end
elseif type(r5) == "string" then
    print("err=" .. r5:sub(1, 200))
end

-- Step 7: Check ipv6_kernel_rw.data after pipe creation
print("")
print("--- IPV6 DATA AFTER PIPE ---")
count = 0
for k, v in pairs(ipv6_kernel_rw.data) do
    count = count + 1
    print(tostring(k) .. "=" .. type(v) .. " " .. tostring(v))
end
print("count=" .. count)

print("=== PROBE 87b COMPLETE ===")
