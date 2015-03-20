-- Copyright (C) Jinhua Luo

local C = require("ljio.cdef")
local ffi = require("ffi")
local epoll = require("ljio.core.epoll")
local timer = require("ljio.core.timer")
require("ljio.core.coroutine")
local utils = require("ljio.core.utils")
local signal = require("ljio.core.signal")
local dfa_compile = require("ljio.core.dfa").compile
local logging = require("ljio.core.logging")
local shdict = require("ljio.core.shdict")
local master = require("ljio.core.master")

local dns = require("ljio.socket.dns")
local ssl = require("ljio.socket.ssl")

local strfind = string.find
local strsub = string.sub
local strmatch = string.match
local tinsert = table.insert
local log = logging.log

local tcp_mt = {__index = {}}

local pools = {}

local YIELD_R = "co_r"
local YIELD_W = "co_w"

local function sock_io_handler(ev, events)
	local sock = ev.sock
	assert(sock)

	if bit.band(events, C.EPOLLIN) ~= 0 then
		if sock[YIELD_R] then
			coroutine.resume(sock[YIELD_R])
		end
	end

	if bit.band(events, C.EPOLLOUT) ~= 0 then
		if sock[YIELD_W] then
			coroutine.resume(sock[YIELD_W])
		end
	end

	if bit.band(events, C.EPOLLRDHUP) ~= 0 then
		if sock[YIELD_R] then
			coroutine.resume(sock[YIELD_R])
			return
		elseif sock[YIELD_W] then
			coroutine.resume(sock[YIELD_W])
			return
		end

		-- no waiting coroutine
		-- just unregister the event to avoid indefinite notify
		if not ev.sock.closed then
			epoll.del_event(ev)
		end

		-- if the sock resides in some pool,
		-- then remove it from the pool and close it.
		if sock.prev then
			local pool
			if sock.pname then pool = pools[sock.pname] end
			if pool then
				sock.next.prev = pool
				pool.next = sock.next
				pool.size = pool.size - 1
				sock:close()
			end
		end
	end
end

local function socket_read(self, rbuf, size)
	local len = C.read(self.fd, rbuf.rp, size)
	local errno = ffi.errno()

	local err
	if len > 0 then
		rbuf.rp = rbuf.rp + len
	elseif len == 0 then
		self:close()
		err = "socket closed"
	elseif errno == C.EAGAIN then
		self:yield(YIELD_R)
	elseif errno ~= C.EINTR then
		self:close()
		err = utils.strerror(errno)
	end
	return len, err
end

local function socket_writev(self, iovec, idx, iovcnt)
	return C.writev(self.fd, iovec[idx], iovcnt)
end

local function tcp_new(fd)
	fd = fd or -1
	local ev = {fd=fd, handler=sock_io_handler}
	local sock = setmetatable({fd=fd, ev=ev, guard=utils.fd_guard(fd),
		stats={rbytes=0,consume=0,wbytes=0}, hook={read=socket_read,write=socket_writev}}, tcp_mt)
	ev.sock = sock
	return sock
end

function tcp_mt.__index.yield(self, rw)
	if self[rw] then return "sock waiting" end
	self[rw] = coroutine.running()
	coroutine.yield()
	self[rw] = nil
end

function tcp_mt.__index.yield_r(self)
	return self:yield(YIELD_R)
end

function tcp_mt.__index.yield_w(self)
	return self:yield(YIELD_W)
end

function tcp_mt.__index.close(self)
	if not self.closed then
		if self.hook.shutdown then
			self.hook.shutdown(self)
		end
		C.close(self.fd)
		self.guard.fd = -1
		self.closed = true
	else
		return nil, "closed"
	end
	return 1
end

function tcp_mt.__index.settimeout(self, msec)
	self.timeout = msec / 1000
end

local READ_CHUNK_SIZE = 4096
local MIN_SPACE = READ_CHUNK_SIZE / 4
local eol1 = string.byte("\r")
local eol2 = string.byte("\n")
ffi.cdef[[ struct buf_gc {void*p;}; ]]
local buf_gc = ffi.metatype("struct buf_gc", {__gc=function(g) C.free(g.p) end})

local function receive_ll(self, pattern)
	if not self.rbuf then
		local buf = C.realloc(nil, READ_CHUNK_SIZE)
		local p = ffi.cast("char*", buf)
		self.rbuf = {buf=p, cp1=p, cp2=p, rp=p, size=READ_CHUNK_SIZE, gc=buf_gc(buf)}
	end

	local rbuf = self.rbuf
	pattern = pattern or "*l"
	local typ = type(pattern)

	while true do
		local avaliable = rbuf.rp - rbuf.cp2
		local no_quota = false

		if self.read_quota and self.stats.rbytes >= self.read_quota then
			local quota = self.read_quota - self.stats.consume
			avaliable = quota - (rbuf.cp2 - rbuf.cp1)
			no_quota = true
		end

		if avaliable > 0 then
			if pattern == "*l" then
				local cp = C.memchr(rbuf.cp2, eol2, avaliable)
				cp = ffi.cast("char*", cp)
				rbuf.cp2 = rbuf.cp2 + avaliable
				if cp ~= nil then
					local sz = cp - rbuf.cp1
					self.stats.consume = self.stats.consume + sz + 1
					if sz > 0 then
						local p = cp - 1
						if p[0] == eol1 then
							sz = sz - 1
						end
					end
					local str = ffi.string(rbuf.cp1, sz)
					rbuf.cp2 = cp + 1
					rbuf.cp1 = rbuf.cp2
					return str
				end
			elseif typ == "number" then
				rbuf.cp2 = rbuf.cp2 + avaliable
				if rbuf.cp2 - rbuf.cp1 >= pattern then
					local str = ffi.string(rbuf.cp1, pattern)
					rbuf.cp1 = rbuf.cp1 + pattern
					rbuf.cp2 = rbuf.cp1
					self.stats.consume = self.stats.consume + pattern
					return str
				end
			elseif typ == "function" then
				local r,err = pattern(self.rbuf, avaliable)
				self.stats.consume = self.stats.consume + (rbuf.cp2 - rbuf.cp1)
				rbuf.cp1 = rbuf.cp2
				if r or err then
					return r,err
				end
			elseif pattern == "*a" then
				rbuf.cp2 = rbuf.cp2 + avaliable
			end
		end

		if no_quota then
			local s = ffi.string(rbuf.cp1, rbuf.cp2 - rbuf.cp1)
			rbuf.cp1 = rbuf.cp2
			self.stats.consume = self.stats.consume + #s
			if pattern == "*a" then
				return s
			end
			return nil, "closed", s
		end

		-- adjust the buffer for next read
		assert(rbuf.rp == rbuf.cp2)
		local space = rbuf.size - (rbuf.rp - rbuf.buf)
		assert(space >= 0)
		if space < MIN_SPACE then
			local reserved = rbuf.cp2 - rbuf.cp1
			assert(reserved >= 0)
			if (rbuf.size - reserved) >= MIN_SPACE then
				if reserved > 0 then
					C.memmove(rbuf.buf, rbuf.cp1, reserved)
					rbuf.cp1 = rbuf.buf
					rbuf.cp2 = rbuf.buf + reserved
					rbuf.rp = rbuf.cp2
				else
					assert(rbuf.rp == rbuf.cp1)
					rbuf.cp1 = rbuf.buf
					rbuf.cp2 = rbuf.buf
					rbuf.rp = rbuf.buf
				end
			else
				local newsize = rbuf.size + READ_CHUNK_SIZE
				local buf = C.realloc(rbuf.buf, newsize)
				assert(buf ~= nil)
				rbuf.buf = ffi.cast("char*", buf)
				rbuf.gc.p = buf
				rbuf.size = newsize
				rbuf.cp1 = rbuf.buf
				rbuf.cp2 = rbuf.buf + reserved
				rbuf.rp = rbuf.cp2
			end
		end

		while true do
			if self.rtimedout then
				local s = ffi.string(rbuf.cp1, rbuf.cp2 - rbuf.cp1)
				rbuf.cp1 = rbuf.cp2
				self.stats.consume = self.stats.consume + #s
				return nil, "timeout", s
			end

			local len, err = self.hook.read(self, rbuf, rbuf.size - (rbuf.rp - rbuf.buf))
			if len > 0 then
				self.stats.rbytes = self.stats.rbytes + len
			end

			if err then
				local s = ffi.string(rbuf.cp1, rbuf.cp2 - rbuf.cp1)
				self.stats.consume = self.stats.consume + #s
				if pattern == "*a" then
					return s
				end
				return nil, err, s
			end

			if len > 0 then
				break
			end
		end
	end
end

function tcp_mt.__index.receive(self, pattern)
	if self.closed then return nil, "socket closed" end

	if self.reading then return nil,"socket busy reading" end
	self.reading = true

	self.rtimedout = false
	if self.timeout and self.timeout > 0 then
		self.rtimer = timer.add_timer(function()
			self.rtimedout = true
			if self[YIELD_R] then
				coroutine.resume(self[YIELD_R])
			end
		end, self.timeout)
	end

	local r,err,partial = receive_ll(self, pattern)

	if self.rtimer then
		self.rtimer:cancel()
		self.rtimer = nil
	end

	self.reading = false
	return r,err,partial
end

function tcp_mt.__index.receiveuntil(self, pattern, options)
	if not pattern or pattern == "" then return nil, "empty pattern" end
	local inclusive = options and options.inclusive

	local dfa = dfa_compile(pattern)
	local node = dfa.start
	local data = ""
	local reset = false

	return function(size)
		assert(size == nil or size > 0)

		if reset then
			reset = false
			node = dfa.start
			if size then
				return nil
			end
		end

		if size and size <= #data then
			local r
			r = strsub(data,1,size)
			data = strsub(data,size+1)
			if node == dfa.last and #data == 0 then
				reset = true
			end
			return r
		elseif node == dfa.last then
			local r = data
			data = ""
			reset = true
			return r
		end

		return self:receive(function(rbuf, avaliable)
			for i = 1,avaliable do
				local c = ffi.string(rbuf.cp2, 1)
				rbuf.cp2 = rbuf.cp2 + 1
				node = node[c]
				if not node then node = dfa.start
				elseif node == dfa.last then break end
			end

			data = data .. ffi.string(rbuf.cp1, rbuf.cp2 - rbuf.cp1)

			local r
			local n_pat = node[3]
			if node ~= dfa.last then
				if size and size <= (#data - n_pat) then
					r = strsub(data,1,size)
					data = strsub(data,size+1)
				end
			else
				if size then
					local l = #data
					if not inclusive then l = l - n_pat end
					if size < l then
						r = strsub(data,1,size)
						data = strsub(data,size+1)
					end
				end
				if not r then
					if inclusive then r = data
					else r = strsub(data,1, #data - n_pat) end
					data = ""
					reset = true
				end
			end
			return r
		end)
	end
end

local MAX_IOVCNT = 64

local function flatten_table(self, data, idx, bytes)
	idx = idx or 0
	bytes = bytes or 0
	local iovec = self.iovec

	for i,v in ipairs(data) do
		local typ = type(v)
		if typ ~= "table" then
			if typ ~= "string" then v = tostring(v) end
			if idx == self.iovec_len then
				-- realloc the iovec array
				self.iovec_len = self.iovec_len + MAX_IOVCNT
				iovec = ffi.new("struct iovec[?]", self.iovec_len)
				ffi.copy(iovec, self.iovec, bytes)
				self.iovec = iovec
			end
			iovec[idx].iov_base = ffi.cast("void *", v)
			local len = #v
			iovec[idx].iov_len = len
			bytes = bytes + len
			idx = idx + 1
		else
			idx, bytes = flatten_table(self, v, idx, bytes)
			if idx == nil then return nil end
		end
	end

	return idx, bytes
end

local function send_ll(self, ...)
	if not self.iovec then
		self.iovec = ffi.new("struct iovec[?]", MAX_IOVCNT)
		self.iovec_len = MAX_IOVCNT
	end

	-- collect and flatten the arguments
	local n_iovec = 0
	local bytes = 0
	local data = select(1, ...)
	local n_args = select("#", ...)
	assert(n_args <= MAX_IOVCNT)
	local typ = type(data)
	if typ == "string" then
		n_iovec = n_args
		for i=0,n_args-1 do
			local s = select(i+1, ...)
			if type(s) ~= "string" then
				return nil, "invalid argument"
			end
			self.iovec[i].iov_base = ffi.cast("void *", s)
			local len = #s
			self.iovec[i].iov_len = len
			bytes = bytes + len
		end
	elseif typ == "table" then
		if n_args > 1 then return nil, "invalid argument" end
		n_iovec, bytes = flatten_table(self, data)
	end

	if n_iovec == nil or n_iovec == 0 or bytes == nil or bytes == 0 then
		return nil, "invalid argument"
	end

	-- do writev()
	local iovec = self.iovec
	local idx = 0
	local sent = 0
	while true do
		if self.wtimedout then
			return sent,"timeout"
		end
		local iovcnt = n_iovec % MAX_IOVCNT
		if iovcnt == 0 then iovcnt = MAX_IOVCNT end
		local len = self.hook.write(self, iovec, idx, iovcnt)
		local errno = ffi.errno()
		if len > 0 then
			self.stats.wbytes = self.stats.wbytes + len
			sent = sent + len
			if sent == bytes then return sent end
			for i=idx,idx+iovcnt-1 do
				if iovec[i].iov_len <= len then
					len = len - iovec[i].iov_len
					idx = idx + 1
					n_iovec = n_iovec - 1
					if len == 0 then break end
				else
					iovec[i].iov_base = ffi.cast("char*", iovec[i].iov_base) + len
					iovec[i].iov_len = iovec[i].iov_len - len
					break
				end
			end
		elseif errno == C.EAGAIN then
			epoll.add_event(self.ev, C.EPOLLOUT)
			self:yield(YIELD_W)
			epoll.del_event(self.ev, C.EPOLLOUT)
		elseif errno ~= C.EINTR then
			self:close()
			return nil, utils.strerror(errno)
		end
	end
end

function tcp_mt.__index.send(self, ...)
	if self.closed then return nil, 'fd closed' end

	self.wtimedout = false
	if self.timeout and self.timeout > 0 then
		self.wtimer = timer.add_timer(function()
			self.wtimedout = true
			if self[YIELD_W] then
				coroutine.resume(self[YIELD_W])
			end
		end, self.timeout)
	end

	local sent,err = send_ll(self, ...)

	if self.wtimer then
		self.wtimer:cancel()
		self.wtimer = nil
	end

	return sent,err
end

function tcp_mt.__index.sendfile(self, path, offset, size)
	local sent = 0
	local err

	if self.use_ssl then
		local f = io.open(path)
		if offset > 0 then f:seek(offset) end
		while true do
			local s = f:read(16*1024)
			if s ~= nil then
				local sent2
				sent2,err = self:send(s)
				sent = sent + sent2
				if err then break end
			else
				f:close()
				break
			end
		end
	else
		local fd = C.open(path, 0)
		assert(fd > 0)
		if offset > 0 then
			assert(C.lseek(fd, offset, C.SEEK_SET) == offset)
		end

		while true do
			local len = C.sendfile(self.fd, fd, nil, size)
			local errno = ffi.errno()

			if len > 0 then
				size = size - len
				sent = sent + len
			end

			if size == 0 then
				break
			end

			if len == 0 then
				err = "sendfile: socket broekn"
				break
			elseif errno == C.EAGAIN then
				epoll.add_event(self.ev, C.EPOLLOUT)
				self:yield(YIELD_W)
				epoll.del_event(self.ev, C.EPOLLOUT)
			elseif errno ~= C.EINTR then
				err = ffi.string(C.strerror(errno))
				break
			end
		end

		assert(C.close(fd) == 0)
	end

	return sent, err
end

local function create_tcp_socket(self, family)
	assert(self.fd == -1)
	local fd = C.socket(self.family, C.SOCKET_STREAM, 0)
	assert(fd > 0)
	utils.set_nonblock(fd)
	self.fd = fd
	self.ev.fd = fd
	self.guard.fd = fd
end

function tcp_mt.__index.bind(self, ip, port)
	local path = strmatch(ip, "unix:(.*)")
	if path then
		C.unlink(path)
		self.family = C.AF_UNIX
		ip = path
	else
		self.family = C.AF_INET
	end

	create_tcp_socket(self)

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

function tcp_mt.__index.listen(self, backlog, handler)
	if self.listening then return 1 end
	backlog = backlog or 1000
	local ret = C.listen(self.fd, backlog)
	if ret ~= 0 then return nil, utils.strerror() end
	self.ev.handler = handler
	epoll.add_event(self.ev, C.EPOLLIN)
	self.listening = true
	return 1
end

function tcp_mt.__index.accept(self)
	local addr
	if self.family == C.AF_INET then
		addr = ffi.new("struct sockaddr_in[1]")
	else
		addr = ffi.new("struct sockaddr_un[1]")
	end
	local len = ffi.new("unsigned int[1]", ffi.sizeof(addr))
	local cfd = C.accept(self.fd, ffi.cast("struct sockaddr *",addr), len)
	if cfd <= 0 then return nil, utils.strerror() end

	utils.set_nonblock(cfd)
	local sock = tcp_new(cfd)
	if self.linfo and self.linfo.ssl then
		ssl.create_ssl(sock, self.srv.sslctx)
		sock.hook.read = ssl.read
		sock.hook.write = ssl.write
		sock.hook.shutdown = ssl.shutdown
		sock.use_ssl = true
	end
	if self.family == C.AF_INET then
		local val = ffi.cast("unsigned short",C.ntohs(addr[0].sin_port))
		sock.port = tonumber(val)
		sock.ip = ffi.string(C.inet_ntoa(addr[0].sin_addr))
	else
		sock.ip = ffi.string(addr[0].sun_addr)
	end

	if self.ip == "*" then
		assert(C.getsockname(cfd, ffi.cast("struct sockaddr *",addr), len) == 0)
		sock.srv_ip = ffi.string(C.inet_ntoa(addr[0].sin_addr))
	else
		sock.srv_ip = self.ip
	end
	sock.srv_port = self.port or "unix"
	epoll.add_event(sock.ev, C.EPOLLIN, C.EPOLLRDHUP, C.EPOLLET)
	return sock
end

function tcp_mt.__index.setkeepalive(self, timeout, size)
	if not self.pname then return nil, "not outgoing connection" end

	local pool = pools[self.pname]
	if not pool then
		pools[self.pname] = {size=0, maxsize=size or 30}
		pool = pools[self.pname]
		pool.prev = pool
		pool.next = pool
	end

	-- tail insert
	pool.prev.next = self
	self.prev = pool.prev
	self.next = pool
	if pool.size + 1 > pool.maxsize then
		-- remove the head (least recently used)
		pool.next.next.prev = pool
		pool.next = pool.next.next
	else
		pool.size = pool.size + 1
	end

	timeout = timeout and (timeout / 1000) or 60
	if timeout > 0 then
		self.keepalive_timer = timer.add_timer(function()
			self.next.prev = self.prev
			self.prev.next = self.next
			self:close()
			pool.size = pool.size - 1
		end, timeout)
	end
	self.closed = true

	return 1
end

function tcp_mt.__index.connect(self, host, port, options_table)
	if self.connected then return nil, "already connected" end

	local path = strmatch(host, "unix:(.*)")
	if path then
		self.family = C.AF_UNIX
		options_table = port
		host = path
	else
		self.family = C.AF_INET
	end

	local pname
	if options_table then pname = options_table.pool end
	if not pname then
		pname = host
		if self.family == C.AF_INET then
			pname = pname .. ":" .. port
		end
	end
	self.pname = pname

	-- look up the connection pool first
	local pool = pools[pname]
	if pool and pool.size > 0 then
		local sock = pool.next
		sock.keepalive_timer:cancel()
		sock.keepalive_timer = nil

		-- copy fields
		self.ip = sock.ip
		self.port = sock.port
		self.fd = sock.fd
		self.ev = sock.ev
		self.ev.sock = self
		self.guard = sock.guard
		self.reusedtimes = sock.reusedtimes
		if not self.reusedtimes then self.reusedtimes = 0 end
		self.reusedtimes = self.reusedtimes + 1
		self.connected = true

		-- update the pool
		sock.next.prev = pool
		pool.next = sock.next
		pool.size = pool.size - 1
		return 1
	end

	-- set connect timer
	self.wtimedout = false
	if self.timeout and self.timeout > 0 then
		self.wtimer = timer.add_timer(function()
			if self[YIELD_W] then
				self.wtimedout = true
				coroutine.resume(self[YIELD_W])
			end
		end, self.timeout)
	end

	-- resolve host and/or port if needed
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

	-- create a new socket
	create_tcp_socket(self)

	-- do non-blocking connect
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

	while true do
		local ret = C.connect(self.fd, ffi.cast("struct sockaddr*",addr), addrlen)
		local errno = ffi.errno()
		if ret == 0 then break end
		if errno == C.EINPROGRESS then
			epoll.add_event(self.ev, C.EPOLLOUT)
			self:yield(YIELD_W)
			epoll.del_event(self.ev, C.EPOLLOUT)
			if self.wtimedout then
				err = "timeout"
				break
			end
			local option = ffi.new("int[1]", 1)
			local len = ffi.new("int[1]", 1)
			assert(C.getsockopt(self.fd, C.SOL_SOCKET, C.SO_ERROR, ffi.cast("void*",option), len) == 0)
			if option[0] ~= 0 then
				err = utils.strerror(err)
			end
			break
		elseif errno ~= EINTR then
			err = utils.strerror(errno)
			break
		end
	end

	if self.wtimer then
		self.wtimer:cancel()
		self.wtimer = nil
	end

	if err then
		self:close()
		return nil, err
	end

	epoll.add_event(self.ev, C.EPOLLIN, C.EPOLLRDHUP, C.EPOLLET)
	self.connected = true
	return 1
end

function tcp_mt.__index.getreusedtimes(self)
	return self.reusedtimes or 0
end

--#--

local g_listen_sk_tbl = {}
local g_tcp_cfg

local function add_ssock(port, address, linfo, srv)
	if g_tcp_cfg == nil or g_tcp_cfg.srv_tbl[port] == nil
		or g_tcp_cfg.srv_tbl[port][address] == nil then
		local ssock = tcp_new()
		ssock.linfo = linfo
		ssock.srv = srv
		local r,err = ssock:bind(address, port)
		if err then error(err) end
		g_listen_sk_tbl[ssock.fd] = ssock
	end
end

local function tcp_parse_conf(cfg)
	local inherited_fdlist = os.getenv("LUAJITIO")
	if inherited_fdlist then
		C.unsetenv("LUAJITIO")
		local addr = ffi.cast("struct sockaddr *", ffi.new("char[512]"))
		local len = ffi.new("unsigned int[1]", ffi.sizeof(addr))
		for fd in string.gmatch(inherited_fdlist, "%d+") do
			fd = tonumber(fd)
			len[0] = 512
			assert(C.getsockname(fd, addr, len) == 0)

			local sock = tcp_new(fd)
			sock.family = addr.sa_family

			if addr.sa_family == C.AF_INET then
				local addr2 = ffi.cast("struct sockaddr_in*", addr)
				sock.ip = ffi.string(C.inet_ntoa(addr2.sin_addr))
				if sock.ip == "0.0.0.0" then
					sock.ip = "*"
				end
				sock.port = C.htons(tonumber(addr2.sin_port))
			else
				local addr2 = ffi.cast("struct sockaddr_un*", addr)
				sock.ip = "unix:" .. ffi.string(addr2.sun_path)
				sock.port = "unix"
			end
			g_listen_sk_tbl[fd] = sock
		end
	end

	local srv_tbl = {}

	for _,srv in ipairs(cfg) do
		if not srv.listen then
			srv.listen = {{address="*", port=((C.getuid() == 0) and 80 or 8000)}}
		end

		for _,linfo in ipairs(srv.listen) do
			local port = linfo.port
			if linfo.address then
				local path = strmatch(linfo.address, "^unix:(.+)$")
				if path then
					port = "unix"
				end
			else
				linfo.address = "*"
			end

			if not srv_tbl[port] then
				srv_tbl[port] = {}
			end

			local address = linfo.address

			if not srv_tbl[port][address] then
				srv_tbl[port][address] = {}
				srv_tbl[port][address].linfo = linfo
				if linfo.default_server then
					srv_tbl[port][address].default_server = srv
				end
			end

			tinsert(srv_tbl[port][address], srv)
		end
	end

	if not inherited_fdlist then
		for port, addresses in pairs(srv_tbl) do
			if addresses["*"] then
				add_ssock(port, "*", addresses["*"].linfo, addresses["*"][1])
			else
				for address, srv_list in pairs(addresses) do
					add_ssock(port, address, srv_list.linfo, srv_list[1])
				end
			end
		end

		for fd, ssock in pairs(g_listen_sk_tbl) do
			if srv_tbl[ssock.port] == nil or srv_tbl[ssock.port][ssock.ip] == nil then
				g_listen_sk_tbl[fd] = nil
				ssock:close()
			end
		end
	else
		for _, ssock in pairs(g_listen_sk_tbl) do
			ssock.linfo = srv_tbl[ssock.port][ssock.ip].linfo
		end
	end

	cfg.srv_tbl = srv_tbl
	cfg.listen_fdlist = g_listen_sk_tbl

	g_tcp_cfg = cfg
end

local function tcp_handler(sock)
	local srv_list = g_tcp_cfg.srv_tbl[sock.srv_port][sock.srv_ip]
		or g_tcp_cfg.srv_tbl[sock.srv_port]["*"]
	local srv = srv_list[1]
	local handler = srv.handler
	if type(handler) == 'string' then
		return require(handler).service(srv)
	elseif type(handler) == 'function' then
		return handler(srv)
	end
end

local function do_all_listen_sk(func)
	for _, ssock in pairs(g_listen_sk_tbl) do
		func(ssock)
	end
end

local function init_worker(conn_handler)
	local shutting_down = false
	local connections = 0
	local wait_listen_sk = false

	local ssock_handler = function(ev)
		local sock,err = ev.sock:accept()
		if sock then
			print("worker pid=" .. C.getpid() .. " get new connection, fd=" .. sock.fd .. ", port=" .. sock.port)
			connections = connections + 1
			if connections >= g_tcp_cfg.worker_connections then
				print("worker pid=" .. C.getpid() .. " unlisten sk")
				do_all_listen_sk(function(ssock) epoll.del_event(ssock.ev) end)
				wait_listen_sk = false
			end
			coroutine.spawn(
				conn_handler,
				function()
					print("worker pid=" .. C.getpid() .. " remove connection, fd=" .. sock.fd)
					sock:close()
					connections = connections - 1

					if shutting_down and connections == 0 then
						os.exit()
					end

					if wait_listen_sk == false and connections < g_tcp_cfg.worker_connections then
						print("worker pid=" .. C.getpid() .. " listen sk")
						do_all_listen_sk(function(ssock) epoll.add_event(ssock.ev, C.EPOLLIN) end)
						wait_listen_sk = true
					end
				end,
				sock
			)
		else
			print("worker pid=" .. C.getpid() .. " accept error: " .. err)
		end
	end

	-- listen all server sockets
	do_all_listen_sk(function(ssock)
		local r,err = ssock:listen(100, ssock_handler)
		if err then error(err) end
	end)
	wait_listen_sk = true

	signal.add_signal_handler(C.SIGQUIT, function()
		if connections == 0 then
			os.exit()
		end
		shutting_down = true
		do_all_listen_sk(function(ssock) epoll.del_event(ssock.ev) end)
	end)

	signal.add_signal_handler(C.SIGTERM, function() os.exit() end)
	signal.add_signal_handler(C.SIGINT, function() os.exit() end)
end

local function run(cfg, parse_conf, conn_handler)
	return master.run(cfg,
		function(cfg) tcp_parse_conf(cfg); if parse_conf then parse_conf(cfg) end end,
		function() return init_worker(conn_handler or tcp_handler) end)
end

return setmetatable({
	new = tcp_new,
}, {
	__call = function(func, ...) return run(...) end
})
