local ffi = require("ffi")
local ep = require("core.epoll_mod")
local timer = require("core.timer_mod")
local co = require("core.co_mod")
local utils = require("core.utils_mod")

ffi.cdef[[
struct in_addr {
	unsigned int  s_addr;
};
struct sockaddr_in {
  short int  sin_family;	 /* Address family			   */
  unsigned short int				sin_port;	   /* Port number				  */
  struct in_addr		sin_addr;	   /* Internet address			 */

  /* Pad to size of `struct sockaddr'. */
  unsigned char		 __pad[16 - sizeof(short int) -
						sizeof(unsigned short int) - sizeof(struct in_addr)];
};
struct sockaddr {
	short int sa_family;
	char sa_data[14];
};
short int ntohs(short int netshort);
short int htons(short int hostshort);
int inet_aton(const char *cp, struct in_addr *inp);
char *inet_ntoa(struct in_addr in);

extern int socket(int domain, int type, int protocol);
extern int bind(int sockfd, const struct sockaddr *addr,
		unsigned int addrlen);
extern int connect(int sockfd, const struct sockaddr *addr,
		   unsigned int addrlen);
extern int listen(int sockfd, int backlog);
extern int accept(int sockfd, struct sockaddr *addr, unsigned int *addrlen);

extern int setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen);

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

typedef struct {
	unsigned long int __val[1024 / (8 * sizeof (unsigned long int))];
} sigset_t;
int signalfd(int fd, const sigset_t *mask, int flags);

typedef unsigned int uint32_t;
typedef int int32_t;
typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef unsigned char uint8_t;
struct signalfd_siginfo {
	uint32_t ssi_signo;
	int32_t ssi_errno;
	int32_t ssi_code;
	uint32_t ssi_pid;
	uint32_t ssi_uid;
	int32_t ssi_fd;
	uint32_t ssi_tid;
	uint32_t ssi_band;
	uint32_t ssi_overrun;
	uint32_t ssi_trapno;
	int32_t ssi_status;
	int32_t ssi_int;
	uint64_t ssi_ptr;
	uint64_t ssi_utime;
	uint64_t ssi_stime;
	uint64_t ssi_addr;
	uint8_t __pad[48];
};
int sigemptyset(sigset_t *set);
int sigaddset(sigset_t *set, int signum);
int sigdelset(sigset_t *set, int signum);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);

typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);

int close(int fd);
int ioctl(int d, int request, ...);
]]

local AF_INET=2
local SOCKET_STREAM=1
local SOL_SOCKET=1
local SO_REUSEADDR=2
local IPPROTO_TCP=6

local SIGCHLD=17
local SIG_BLOCK=0
local SIG_IGN=1
local SIG_ERR=-1
local SIGPIPE=13

local EAGAIN = 11
local EINTR = 4

local READ_ALL = 1
local READ_LINE = 2
local READ_LEN = 3

local io_mt = {__index = {}}
local MAX_RBUF_LEN = 4096

function io_mt.__index.close(self)
	if not self.closed then
		ffi.C.close(self.fd)
		self.guard.fd = -1
		self.closed = true
	end
end

function io_mt.__index.receive(self, pattern)
	if self.closed then return nil, 'fd closed' end

	if not self.rbuf_c then self.rbuf_c = ffi.new("char[?]", MAX_RBUF_LEN) end
	if not self.rbuf then self.rbuf = "" end
	local mode
	if not pattern or pattern == '*l' then
		mode = READ_LINE
	elseif pattern == '*a' then
		mode = READ_ALL
	elseif type(pattern) == 'number' then
		mode = READ_LEN
	end

	while true do
		if self.rbuf ~= "" then
			if mode == READ_LINE then
				local la,lb = string.find(self.rbuf, '\r\n')
				if la then
					local str = string.sub(self.rbuf, 1, la-1)
					self.rbuf = string.sub(self.rbuf, lb+1)
					return str
				end
			elseif mode == READ_LEN and #self.rbuf >= pattern then
				local str = string.sub(self.rbuf, 1, pattern)
				self.rbuf = string.sub(self.rbuf, pattern+1)
				return str
			end
		end

		local len = ffi.C.read(self.fd, self.rbuf_c, MAX_RBUF_LEN)
		local errno = ffi.errno()
		if len > 0 then
			self.rbuf = self.rbuf .. ffi.string(self.rbuf_c, len)
		elseif len == 0 then
			-- for socket, means broken?
			-- how about for fd of other types?
			return nil, 'socket broken'
		elseif errno == EAGAIN then
			if self.rbuf ~= "" and mode == READ_ALL then
				local str = self.rbuf
				self.rbuf = ""
				return str
			else
				local err = co.yield(co.YIELD_IO, self.fd)
				if err then return nil,err end
			end
		elseif errno ~= EINTR then
			return nil, utils.strerror()
		end
	end
end

function io_mt.__index.send(self, ...)
	if self.closed then return nil, 'fd closed' end

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
	while true do
		if total == 0 then return true end
		local len = ffi.C.writev(self.fd, iovec[idx], iovcnt)
		local errno = ffi.errno()
		if len == total then
			return true
		elseif len > 0 then
			total = total - len
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
			return false, utils.strerror()
		end
	end
end

local function sock_new(fd, ip, port)
	return setmetatable({fd=fd, ip=ip, port=port, ev={fd=fd}, guard=utils.fd_guard(fd)}, io_mt)
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

function io_mt.__index.accept(self)
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

	-- block and capture SIGCHLD
	local mask = ffi.new("sigset_t")
	ffi.C.sigemptyset(mask)
	ffi.C.sigaddset(mask, SIGCHLD)
	ffi.C.sigprocmask(SIG_BLOCK, mask, NULL)
	local xfd = ffi.C.signalfd(-1, mask, 0)

	-- avoid crash triggered by SIGPIPE
	ffi.C.signal(SIGPIPE, ffi.cast("sighandler_t",SIG_IGN))

	for i=1,g_tcp_cfg.worker_processes do
		local pid = ffi.C.fork()
		if pid == 0 then
			print("child pid=" .. ffi.C.getpid() .. " enter")
			ffi.C.close(xfd)

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
			ep.init(nil, function()
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
	local worker_processes = g_tcp_cfg.worker_processes
	ep.init(nil, function()
		assert(worker_processes >= 0)
		return -1, (worker_processes == 0)
	end)

	do_all_listen_sk(function(ssock) ssock:close() end)
	print("> parent wait " .. worker_processes .. " child")
	local signal_ev = {fd = xfd, handler = function()
		local siginfo = ffi.new("struct signalfd_siginfo")
		assert(ffi.C.read(xfd, siginfo, ffi.sizeof("struct signalfd_siginfo")) == ffi.sizeof("struct signalfd_siginfo"))
		print ("> child exit with pid=" .. siginfo.ssi_pid .. ", status=" .. siginfo.ssi_status)
		worker_processes = worker_processes - 1
	end}
	ep.add_event(signal_ev, ep.EPOLLIN)
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
