local ffi = require("ffi")
local ep = require("core.epoll_mod")
local timer = require("core.timer_mod")
local co = require("core.co_mod")
local utils = require("core.utils_mod")
local signal = require("core.signal_mod")
require("socket.base")

ffi.cdef[[
typedef int ssize_t;
typedef unsigned int size_t;
extern ssize_t read(int fd, void *buf, size_t count);
extern ssize_t write(int fd, const void *buf, size_t count);

struct iovec {
   void  *iov_base;    /* Starting address */
   size_t iov_len;     /* Number of bytes to transfer */
};
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);

int fork(void);
int getpid(void);

int close(int fd);
int ioctl(int d, int request, ...);
]]

local AF_INET=2
local SOCKET_STREAM=1
local SOL_SOCKET=1
local SO_REUSEADDR=2
local IPPROTO_TCP=6

local SIGCHLD=17
local SIGPIPE=13

local EAGAIN = 11
local EINTR = 4

local READ_ALL = 1
local READ_LINE = 2
local READ_LEN = 3
local READ_UNTIL = 4

local tcp_mt = {__index = {}}
local MAX_RBUF_LEN = 4096

function tcp_mt.__index.close(self)
	if not self.closed then
		ffi.C.close(self.fd)
		self.guard.fd = -1
		self.closed = true
	end
end

function tcp_mt.__index.settimeout(sec)
	self.timeout = sec
end

local function receive_ll(self, pattern, rlen, options)
	if not self.rbuf_c then self.rbuf_c = ffi.new("char[?]", MAX_RBUF_LEN) end
	if not self.rbuf then self.rbuf = "" end

	local mode
	if not pattern or pattern == '*l' then
		mode = READ_LINE
	elseif pattern == '*a' then
		mode = READ_ALL
	elseif type(pattern) == 'number' then
		mode = READ_LEN
	else
		mode = READ_UNTIL
	end

	while true do
		local rbuf_len = #self.rbuf
		if rbuf_len > 0 then
			if mode == READ_LINE then
				local la,lb = string.find(self.rbuf, '\r\n')
				if la then
					local str = string.sub(self.rbuf, 1, la-1)
					self.rbuf = string.sub(self.rbuf, lb+1)
					return str
				end
			elseif mode == READ_LEN then
				if rbuf_len >= pattern then
					local str = string.sub(self.rbuf, 1, pattern)
					self.rbuf = string.sub(self.rbuf, pattern+1)
					return str
				end
			elseif mode == READ_UNTIL then
				local i,j
				if not self.last_matched then
					i,j = string.find(self.rbuf, pattern)
					if i then self.last_matched = {i=i,j=j} end
				else
					i,j = self.last_matched.i, self.last_matched.j
				end
				if i then
					if i == 1 then
						if option.inclusive then
							self.rbuf = string.sub(self.rbuf, j + 1)
						end
						self.last_matched = nil
						return nil
					end
					if option.inclusive then i = j else i = i - 1 end
					if rlen and rlen < i then i = rlen end
					local str = string.sub(self.rbuf, 1, i)
					self.rbuf = string.sub(self.rbuf, i + 1)
					self.last_matched.i = self.last_matched.i - i
					self.last_matched.j = self.last_matched.j - i
					assert(self.last_matched.j >= 0)
					if self.last_matched.j == 0 then
						self.last_matched.i = 1
					end
					return str
				elseif rlen and rlen <= rbuf_len then
					local str = string.sub(self.rbuf, 1, rlen)
					self.rbuf = string.sub(self.rbuf, rlen+1)
					return str
				end
			end
		end

		while true do
			if self.rtimedout then
				assert(self.last_matched == nil)
				local str = self.rbuf
				self.rbuf = ""
				return nil, "timeout", self.rbuf
			end

			local err
			local len = ffi.C.read(self.fd, self.rbuf_c, MAX_RBUF_LEN)
			local errno = ffi.errno()

			if len > 0 then
				self.rbuf = self.rbuf .. ffi.string(self.rbuf_c, len)
				break
			elseif len == 0 then
				-- for socket, means closed by peer?
				-- how about other types of fd?
				self:close()
				err = "socket closed"
			elseif errno == EAGAIN then
				co.yield(co.YIELD_IO, self.fd)
			elseif errno ~= EINTR then
				self:close()
				err = utils.strerror(errno)
			end

			if err then
				local rbuf_len = #self.rbuf
				local str
				if rbuf_len > 0 then
					str = self.rbuf
					self.rbuf = ""
					if mode == READ_ALL then
						return str
					end
				end
				return nil, err, str
			end
		end
	end
end

local function wakeup_timedout(cur_co)
	if coroutine.status(cur_co) == "suspended" then
		local colist = co.wait_io_list[self.fd]
		for i=1,#colist do
			if colist[i] == cur_co then
				table.remove(colist,i)
				co.co_resume(cur_co)
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
		local cur_co = coroutine.running()
		assert(cur_co)
		self.rtimer = timer.add_timer(function()
			self.rtimedout = true
			wakeup_timedout(cur_co)
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

function tcp_mt.__index.receiveutil(self, pattern, options)
	return function(len)
		return self:receive(pattern, len, options)
	end
end

function send_ll(self, ...)
	if not self.iovec then
		self.iovec = ffi.new("struct iovec[?]", 64)
	end
	local iovec = self.iovec
	local total = 0
	local iovcnt = select('#', ...)
	for i=0,iovcnt-1 do
		local s = select(i+1, ...)
		iovec[i].iov_base = ffi.cast("void *", s)
		local len = #s
		iovec[i].iov_len = len
		total = total + len
	end

	local idx = 0
	local gc = {}
	local sent = 0
	while true do
		if self.wtimedout then
			return sent,"timeout"
		end
		local len = ffi.C.writev(self.fd, iovec[idx], iovcnt)
		local errno = ffi.errno()
		if len > 0 then sent = sent + len end
		if sent == total then
			return sent
		elseif len > 0 then
			for i=idx,iovcnt-1 do
				if iovec[i].io_len <= len then
					len = len - iovec[i].io_len
					idx = idx + 1
					iovcnt = iovcnt - 1
					if len == 0 then break end
				else
					local str = string.sub(iovec[i].iov_base, len + 1)
					table.insert(gc, str)
					iovec[i].iov_base = ffi.cast("void*", str)
					iovec[i].iov_len = iovec[i].iov_len - len
					break
				end
			end
		elseif errno == EAGAIN then
			ep.add_event(self.ev, ep.EPOLLOUT)
			co.yield(co.YIELD_IO, self.fd)
			ep.del_event(self.ev, ep.EPOLLOUT)
		elseif errno ~= EINTR then
			self:close()
			return nil, utils.strerror(errno)
		end
	end
end

function tcp_mt.__index.send(self, ...)
	if self.closed then return nil, 'fd closed' end

	self.wtimedout = false
	if self.timeout and self.timeout > 0 then
		local cur_co = coroutine.running()
		assert(cur_co)
		self.wtimer = timer.add_timer(function()
			self.wtimedout = true
			wakeup_timedout(cur_co)
		end, self.timeout)
	end

	local sent,err = send_ll(self, ...)

	if self.wtimer then
		self.wtimer:cancel()
		self.wtimer = nil
	end

	return sent,err
end

local function sock_new(fd, ip, port)
	return setmetatable({fd=fd, ip=ip, port=port, ev={fd=fd}, guard=utils.fd_guard(fd)}, tcp_mt)
end

local function bind(ip, port, listen_size)
	listen_size = listen_size or 1000
	local sk = ffi.C.socket(AF_INET, SOCKET_STREAM, 0)
	assert(sk > 0)
	utils.set_nonblock(sk)
	local option = ffi.new("int[1]", 1)
	assert(ffi.C.setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, ffi.cast("void*",option), ffi.sizeof("int")) == 0)
	local addr = ffi.new("struct sockaddr_in")
	addr.sin_family = AF_INET
	addr.sin_port = ffi.C.htons(tonumber(port))
	ffi.C.inet_aton(ip, addr.sin_addr)
	if ffi.C.bind(sk, ffi.cast("struct sockaddr*",addr), ffi.sizeof(addr)) == -1 then
		return nil, utils.strerrno()
	end
	assert(ffi.C.listen(sk, listen_size) == 0)
	local sock = sock_new(sk, ip, port)
	sock.listen = ip .. ":" .. port
	return sock
end

function tcp_mt.__index.accept(self)
	local client_addr = ffi.new("struct sockaddr_in[1]")
	local in_addr_len = ffi.new("unsigned int[1]")
	local cfd = ffi.C.accept(self.fd, ffi.cast("struct sockaddr *",client_addr), in_addr_len)
	if cfd <= 0 then return nil, utils.strerror() end
	local val = ffi.cast("unsigned short",ffi.C.ntohs(client_addr[0].sin_port))
	local port = tonumber(val)
	local ip = ffi.string(ffi.C.inet_ntoa(client_addr[0].sin_addr))
	utils.set_nonblock(cfd)
	local sock = sock_new(cfd, ip, port)
	sock.listen = self.listen
	return sock
end

--#--

local g_listen_sk_tbl = {}
local g_tcp_cfg
local function tcp_parse_conf(cf)
	g_tcp_cfg = cf
	local srv_tbl = {}
	for _,srv in ipairs(g_tcp_cfg) do
		for ip,port in string.gmatch(srv.listen, "([%d%.%*]+):(%d+)") do
			if not srv_tbl[port] then srv_tbl[port] = {} end
			if ip == '*' then
				srv_tbl[port] = {['*']=1}
			elseif not srv_tbl[port]['*'] then
				srv_tbl[port][ip] = 1
			end
		end
	end

	for port,ip_set in pairs(srv_tbl) do
		for ip,_ in pairs(ip_set) do
			local sock,err = bind(ip, port)
			if err then error(err) end
			g_listen_sk_tbl[sock.fd] = sock
		end
	end
end

local function tcp_handler(sock)
	local target_srv
	local host = req.headers["host"]
	for _,srv in ipairs(g_http_cfg) do
		if string.find(srv.listen, sock.listen, 1, true) then
			local handler = srv.handler
			assert(handler)
			local typ = type(handler)
			if typ == "string" then
				return (assert(require(handler))).service(srv)
			elseif type == "function" then
				return handler(srv)
			end
		end
	end
	print "no handler"
end

local function do_all_listen_sk(func)
	for _,ssock in pairs(g_listen_sk_tbl) do
		func(ssock)
	end
end

local function run(cfg, overwrite_handler)
	local conn_handler = overwrite_handler or tcp_handler
	tcp_parse_conf(cfg)

	local worker_processes = g_tcp_cfg.worker_processes
	local sigchld_handler = function(siginfo)
		print ("> child exit with pid=" .. siginfo.ssi_pid .. ", status=" .. siginfo.ssi_status)
		worker_processes = worker_processes - 1
	end
	signal.add_signal_handler(SIGCHLD, sigchld_handler)

	-- avoid crash triggered by SIGPIPE
	signal.ignore_signal(SIGPIPE)

	for i=1,worker_processes do
		local pid = ffi.C.fork()
		if pid == 0 then
			print("child pid=" .. ffi.C.getpid() .. " enter")
			signal.del_signal_handler(SIGCHLD, sigchld_handler)

			local connections = 0
			local wait_listen_sk = false

			local fd_handler = function(ev, events)
				local co_list = co.wait_io_list[ev.fd]
				local n_co = 0
				if co_list then
					n_co = #co_list
					for i=1,n_co do
						co.resume(co_list[1])
						table.remove(co_list,1)
					end
				end
				if n_co == 0 and bit.band(events, ep.EPOLLRDHUP) ~= 0 then
					print("EPOLLRDHUP happens, fd=" .. ev.fd)
					ep.del_event(ev)
				end
			end

			local ssock_handler = function(ev)
				local sock,err = ev.ssock:accept()
				if sock then
					print("child pid=" .. ffi.C.getpid() .. " get new connection, cfd=" .. sock.fd .. ", port=" .. sock.port)
					connections = connections + 1
					if connections >= g_tcp_cfg.worker_connections then
						print("child pid=" .. ffi.C.getpid() .. " unlisten sk")
						do_all_listen_sk(function(ssock) ep.del_event(ssock.ev) end)
						wait_listen_sk = false
					end
					sock.ev.handler = fd_handler
					ep.add_event(sock.ev, ep.EPOLLIN, ep.EPOLLRDHUP, ep.EPOLLET)
					co.spawn(
						function()
							local r1,r2 = pcall(function() return conn_handler(sock) end)
							if r1 == false then print(r2); os.exit(1) end
							return r2
						end,
						function()
							print("child pid=" .. ffi.C.getpid() .. " remove connection, cfd=" .. sock.fd)
							sock:close()
							connections = connections - 1
						end
					)
				else
					print("child pid=" .. ffi.C.getpid() .. " accept error: " .. err)
				end
			end

			-- init the event loop
			ep.init()
			ep.add_prepare_hook(function()
				-- listen all server sockets
				if (not wait_listen_sk) and connections < g_tcp_cfg.worker_connections then
					print("child pid=" .. ffi.C.getpid() .. " listen sk")
					do_all_listen_sk(function(ssock) ep.add_event(ssock.ev, ep.EPOLLIN) end)
					wait_listen_sk = true
				end

				-- wakeup idle threads
				local wait_timeout = -1
				for i=1,#co.idle_list do
					co.resume(co.idle_list[1])
					table.remove(co.idle_list,1)
				end
				if #co.idle_list > 0 then wait_timeout = 0 end

				return wait_timeout;
			end)

			-- init signal subsystem
			signal.init()

			-- init timer subsystem
			timer.init()

			-- init all listening sockets
			do_all_listen_sk(function(ssock)
				ssock.ev.handler = ssock_handler
				ssock.ev.ssock = ssock
				ep.add_event(ssock.ev, ep.EPOLLIN)
			end)

			-- run the event loop
			ep.run()
			print("child pid=" .. ffi.C.getpid() .. " exit")
			os.exit(0)
		end
	end

	-- master event loop
	ep.init()
	ep.add_prepare_hook(function()
		assert(worker_processes >= 0)
		return -1, (worker_processes == 0)
	end)
	signal.init()
	print("> parent wait " .. worker_processes .. " child")
	ep.run()
	print "> parent exit"
	os.exit(0)
end

return setmetatable({
	connect = tcp_connect,
	bind = bind,
	accept = accept,
}, {
	__call = function(func, ...) return run(...) end
})
