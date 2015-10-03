-- Copyright (C) Jinhua Luo

local ffi = require("ffi")
local C = require("ljio.cdef")
local tcp = require("ljio.socket.tcp")
local dns = require("ljio.socket.dns")

local in_addr = ffi.new("struct in_addr")
local addr_in = ffi.new("struct sockaddr_in")
local in_addr_t_sz = ffi.sizeof("in_addr_t")
local in_port_t_sz = ffi.sizeof("in_port_t")
local tmp1 = ffi.new("in_addr_t[1]")
local tmp2 = ffi.new("in_port_t[1]")
local tmp3 = ffi.new("char[?]", in_addr_t_sz)
local tmp4 = ffi.new("socklen_t[1]")

local function read_data(rbuf, avaliable)
    local data = ffi.string(rbuf.cp2, avaliable)
    rbuf.cp2 = rbuf.cp2 + avaliable
    return data
end

local function transfer_data(sock1, sock2)
    local data, err = sock1:receive(read_data)
    if err then
        return
    end

    local sent, err = sock2:send(data)
    if err then
        return
    end
    return transfer_data(sock1, sock2)
end

local function server(sock)
    local data = sock:receive(2)
    local nmethods = string.byte(data:sub(2, 2))
    sock:receive(nmethods)
    sock:send("\x05\x00")

    local data, err = sock:receive(4)
    if err then
        return
    end
    local cmd = string.byte(data:sub(2, 2))
    if cmd ~= 1 then
        sock:send('\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
        return
    end

    local atyp = string.byte(data:sub(4, 4))
    local addr
    if atyp == 1 then
        addr = sock:receive(4)
        tmp1 = ffi.cast("in_addr_t*", addr)
        in_addr.s_addr = tmp1
        addr = ffi.string(C.inet_ntoa(in_addr))
    elseif atyp == 3 then
        local len = sock:receive(1)
        len = string.byte(len)
        addr = sock:receive(len)
    end

    local port = sock:receive(2)
    port = string.byte(port:sub(1, 1)) * 256 + string.byte(port:sub(2, 2))

    local remote, err = tcp.new()
    local ret, err = remote:connect(addr, port)
    if err then
        print("connect: addr=" .. addr .. ", port=" .. port .. ", err=" .. err)
        sock:send('\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
        return
    end

    local reply = '\x05\x00\x00\x01'
    C.getsockname(remote.fd, ffi.cast("struct sockaddr *", addr_in), tmp4)
    tmp1[0] = addr_in.sin_addr.s_addr
    ffi.copy(tmp3, tmp1, in_addr_t_sz)
    reply = reply .. ffi.string(tmp3, in_addr_t_sz)
    tmp2[0] = addr_in.sin_port
    ffi.copy(tmp3, tmp2, in_port_t_sz)
    reply = reply .. ffi.string(tmp3, in_port_t_sz)

    local sent, err = sock:send(reply)
    if err then
        return
    end

    local co1 = coroutine.create(transfer_data)
    coroutine.resume(co1, sock, remote)
    local co2 = coroutine.create(transfer_data)
    coroutine.resume(co2, remote, sock)
    coroutine.wait(co1)
    coroutine.wait(co2)
end

return server
