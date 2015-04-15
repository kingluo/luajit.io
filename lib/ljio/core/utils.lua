-- Copyright (C) Jinhua Luo

local C = require("ljio.cdef")
local ffi = require("ffi")
local bit = require("bit")

ffi.cdef[[
struct fd_guard {int fd;};
]]

local fd_guard = ffi.metatype("struct fd_guard", {
    __gc = function(g)
        if g.fd > 0 then ffi.C.close(g.fd) end
    end
})

local FIONBIO=0x5421
local non_block_flag = ffi.new("int[1]",1)
local function set_nonblock(fd)
    assert(ffi.C.ioctl(fd, FIONBIO, non_block_flag) == 0)
end

local function strerror(errno)
    return ffi.string(ffi.C.strerror(errno or ffi.errno()))
end

local function bin2hex(s)
    s = string.gsub(s,"(.)",function (x) return string.format("%x",string.byte(x)) end)
    return s
end

local v_time_t = ffi.new("time_t[1]")
local date_buf = ffi.new("char[?]", 200)
local tm = ffi.new("struct tm[1]")
local function http_time(t)
    if t then
        v_time_t[0] = t
    else
        C.time(v_time_t)
    end
    assert(C.gmtime_r(v_time_t, tm))
    local len = C.strftime(date_buf, 200, "%a, %d %h %G %H:%M:%S GMT", tm)
    assert(len > 0)
    return ffi.string(date_buf, len)
end

local function normalize_lua_path(path)
    local path_max = 4096
    local prefix = ffi.new("char[?]", path_max)
    assert(C.getcwd(prefix, path_max) == prefix)
    prefix = ffi.string(prefix)
    local t = {}
    for p in string.gmatch(path, "[^;]+") do
        if string.sub(p,1,1) ~= "/" then
            p = prefix .. "/" .. p
        end
        table.insert(t, p)
    end
    return table.concat(t, ";")
end

return {
    fd_guard = fd_guard,
    set_nonblock = set_nonblock,
    strerror = strerror,
    bin2hex = bin2hex,
    http_time = http_time,
    normalize_lua_path = normalize_lua_path,
}
