-- Copyright (C) Jinhua Luo

local C = require("ljio.cdef")
local ffi = require("ffi")
local epoll = require("ljio.core.epoll")
local timer = require("ljio.core.timer")
local utils = require("ljio.core.utils")
local log = require("ljio.core.logging").log

local dns = require("ljio.socket.dns")

local strfind = string.find
local strsub = string.sub
local strmatch = string.match
local tinsert = table.insert
local tconcat = table.concat

local udp_mt = {__index = {}}

local YIELD_R = "co_r"

local READ_CHUNK_SIZE = 8192

local addrlen = ffi.new("socklen_t[1]")
local addr_in = ffi.new("struct sockaddr_in")
local addr_un = ffi.new("struct sockaddr_un")

local function sock_io_handler(ev, events)
    local sock = ev.sock
    assert(sock)

    if bit.band(events, C.EPOLLIN) ~= 0 then
        if sock[YIELD_R] then
            coroutine.resume(sock[YIELD_R])
        end
    end
end

local function udp_new(fd)
    fd = fd or -1
    local ev = {fd=fd, handler=sock_io_handler}
    local sock = setmetatable({fd=fd, ev=ev, guard=utils.fd_guard(fd),
        stats={rbytes=0,consume=0,wbytes=0}}, udp_mt)
    ev.sock = sock
    return sock
end

local function return_yield(self, rw, ...)
    self[rw] = nil
    return ...
end

function udp_mt.__index.yield(self, rw)
    if self[rw] then return "sock waiting" end
    self[rw] = coroutine.running()
    return return_yield(self, rw, coroutine.yield())
end

function udp_mt.__index.yield_r(self)
    return self:yield(YIELD_R)
end

function udp_mt.__index.close(self)
    if not self.closed then
        C.close(self.fd)
        self.guard.fd = -1
        self.closed = true
    else
        return nil, "closed"
    end
    return 1
end

function udp_mt.__index.settimeout(self, msec)
    self.timeout = msec == nil and nil or msec / 1000
end

local function read_timeout_handler(args)
    local self = args[1]
    self.rtimedout = true
    if self[YIELD_R] then
        coroutine.resume(self[YIELD_R])
    end
end

function udp_mt.__index.receive(self, size)
    if self.closed then return nil, "closed" end

    size = size or READ_CHUNK_SIZE
    if self.rbuf == nil or self.rbuf_size < size then
        self.rbuf = ffi.new("char[?]", size)
        self.rbuf_size = size
    end

    self.rtimedout = false
    if self.timeout and self.timeout > 0 then
       self.rtimer = timer.add_timer(read_timeout_handler, self.timeout, self)
    end

    local addr = self.family == C.AF_INET and addr_in or add_un

    local data, err, ip, port

    while true do
        size = C.recvfrom(self.fd, self.rbuf, size, 0, ffi.cast("struct sockaddr*", addr), addrlen)
        if size > 0 then
            data = ffi.string(self.rbuf, size)
            break
        elseif size == -1 then
            local errno = ffi.errno()
            if errno == C.EAGAIN then
                epoll.add_event(self.ev, C.EPOLLIN, C.EPOLLET)
                self:yield_r()
                epoll.del_event(self.ev, C.EPOLLIN, C.EPOLLET)
                if self.rtimedout then
                    err = "timeout"
                    break
                end
            else
                err = utils.strerror(errno)
            end
        end
    end

    if self.rtimer then
       self.rtimer:cancel()
       self.rtimer = nil
    end

    return data, err, ip, port
end

local function copy_table(dst, t)
    for i = 1, #t do
        local v = t[i]
        local typ = type(v)
        if typ == "table" then
            copy_table(dst, v)
        else
            if typ == "boolean" then
                v = v and "true" or "false"
            elseif typ == "nil" then
                v = "nil"
            elseif typ ~= "string" then
                v = tostring(v)
            end
            tinsert(dst, v)
        end
    end
end

function udp_mt.__index.send(self, data)
    if self.closed then return nil, 'fd closed' end

    if type(data) == "table" then
        local buf = {}
        copy_table(buf, data)
        data = tconcat(buf)
    end

    local sent = C.write(self.fd, data, #data)
    local ret = 1
    local err
    if sent == -1 then
        ret = nil
        err = utils.strerror()
    end

    return ret, err
end

local function create_udp_socket(self)
    assert(self.fd == -1)
    local fd = C.socket(self.family, C.SOCK_DGRAM, 0)
    assert(fd > 0)
    utils.set_nonblock(fd)
    self.fd = fd
    self.ev.fd = fd
    self.guard.fd = fd
end

function udp_mt.__index.setsockname(self, ip, port)
    local path = strmatch(ip, "unix:(.*)")
    if path then
        C.unlink(path)
        self.family = C.AF_UNIX
        ip = path
    else
        self.family = C.AF_INET
    end

    create_udp_socket(self)

    local addr, addrlen
    if self.family == C.AF_INET then
        local option = ffi.new("int[1]", 1)
        assert(C.setsockopt(self.fd, C.SOL_SOCKET, C.SO_REUSEADDR, ffi.cast("void*",option), ffi.sizeof("int")) == 0)
        addr = ffi.new("struct sockaddr_in")
        addr.sin_family = C.AF_INET
        addr.sin_port = C.htons(tonumber(port))
        C.inet_aton(ip, addr.sin_addr)
        addrlen = ffi.sizeof(addr)
    else
        addr = ffi.new("struct sockaddr_un")
        addr.sun_family = C.AF_UNIX
        addr.sun_path = ip
        addrlen = ffi.offsetof(addr, "sun_path") + #ip + 1
    end

    if C.bind(self.fd, ffi.cast("struct sockaddr*",addr), addrlen) == -1 then
        return nil, utils.strerror()
    end

    self.ip = ip
    self.port = port
    return 1
end

function udp_mt.__index.setpeername(self, host, port)
    if self.connected then return nil, "already connected" end

    local path = strmatch(host, "unix:(.*)")
    if path then
        self.family = C.AF_UNIX
        host = path
    else
        self.family = C.AF_INET
    end

    if self.family == C.AF_INET
        and (strfind(host, "^%d+%.%d+%.%d+%.%d+$") == nil or type(port) ~= "number") then
        self.resolve_key = dns.resolve(host, port, function(ip, port)
            coroutine.resume(self[YIELD_W], ip, port)
        end)

        host, port = self:yield(YIELD_W)
        local err
        if self.wtimedout then
            dns.cancel_resolve(self.resolve_key)
            self.resolve_key = nil
            err = "timeout"
        elseif host == nil or port == nil then
            err = "resolve failed"
        end
        if err then
            if self.wtimer then
                self.wtimer:cancel()
                self.wtimer = nil
            end
            return nil, err
        end
    end

    create_udp_socket(self)

    self.ip = host
    self.port = port
    local addr, addrlen
    if self.family == C.AF_INET then
        addr = ffi.new("struct sockaddr_in")
        addr.sin_family = C.AF_INET
        addr.sin_port = C.htons(tonumber(port))
        C.inet_aton(host, addr.sin_addr)
        addrlen = ffi.sizeof(addr)
    else
        addr = ffi.new("struct sockaddr_un")
        addr.sun_family = C.AF_UNIX
        addr.sun_path = host
        addrlen = ffi.offsetof(addr, "sun_path") + #host + 1
    end

    local err
    local ret = C.connect(self.fd, ffi.cast("struct sockaddr*",addr), addrlen)
    if ret ~= 0 then
        ret = nil
        err = utils.strerror()
        self:close()
    else
        ret = 1
        self.connected = true
    end

    return ret, err
end

return udp_new
