#!/usr/bin/env luajit

local ffi = require("ffi")
local bit = require("bit")

ffi.cdef[[
extern int errno;

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

char *strerror(int errnum);

typedef int ssize_t;
typedef unsigned int size_t;
extern ssize_t read(int fd, void *buf, size_t count);
extern ssize_t write(int fd, const void *buf, size_t count);

typedef union epoll_data {
	void		*ptr;
	int		  fd;
	int	 u32;
	long	 u64;
} epoll_data_t;

struct epoll_event {
	int	 events;	  /* Epoll events */
	epoll_data_t data;		/* User data variable */
};

extern int epoll_create(int size);
extern int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
extern int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

extern int setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen);

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

unsigned int sleep(unsigned int seconds);
int close(int fd);
int ioctl(int d, int request, ...);

typedef int time_t;
typedef long suseconds_t;
time_t time(time_t *t);
struct tm {
   int tm_sec;         /* seconds */
   int tm_min;         /* minutes */
   int tm_hour;        /* hours */
   int tm_mday;        /* day of the month */
   int tm_mon;         /* month */
   int tm_year;        /* year */
   int tm_wday;        /* day of the week */
   int tm_yday;        /* day in the year */
   int tm_isdst;       /* daylight saving time */
};
struct tm *gmtime(const time_t *timep);
struct tm *localtime(const time_t *timep);

struct timeval {
	time_t      tv_sec;     /* seconds */
	suseconds_t tv_usec;    /* microseconds */
};
struct timezone {
	int tz_minuteswest;     /* minutes west of Greenwich */
	int tz_dsttime;         /* type of DST correction */
};
int gettimeofday(struct timeval *tv, struct timezone *tz);
size_t strftime(char *s, size_t max, const char *format, const struct tm *tm);

struct timespec {
   time_t tv_sec;                /* Seconds */
   long   tv_nsec;               /* Nanoseconds */
};

int clock_gettime(int clk_id, struct timespec *tp);

struct itimerspec {
   struct timespec it_interval;  /* Interval for periodic timer */
   struct timespec it_value;     /* Initial expiration */
};
int timerfd_create(int clockid, int flags);

int timerfd_settime(int fd, int flags,
				   const struct itimerspec *new_value,
				   struct itimerspec *old_value);

typedef uint64_t eventfd_t;
int eventfd(unsigned int initval, int flags);
int eventfd_read(int fd, eventfd_t *value);
int eventfd_write(int fd, eventfd_t value);

struct iovec {
   void  *iov_base;    /* Starting address */
   size_t iov_len;     /* Number of bytes to transfer */
};
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
]]

EPOLL_CTL_ADD=1
EPOLL_CTL_DEL=2
EPOLL_CTL_MOD=3

EPOLLIN=0x1
EPOLLPRI=0x2
EPOLLOUT=0x4
EPOLLERR=0x8
EPOLLHUP=0x10
EPOLLET=0x8000
EPOLLRDHUP = 0x2000

AF_INET=2
SOCKET_STREAM=1

SOL_SOCKET=1
SO_REUSEADDR=2

SIGCHLD=17
SIG_BLOCK=0

FIONBIO=0x5421

CLOCK_MONOTONIC=1

EAGAIN = 11
EINTR = 4

IPPROTO_TCP=6
TCP_CORK=3

CLOCK_MONOTONIC_RAW=4

-- coroutine yield flag
YIELD_IO = 1
YIELD_SLEEP = 2
YIELD_IDLE = 3
YIELD_EXIT = 4
YIELD_WAIT = 5

function bind(fd, ip, port)
   local addr = ffi.new("struct sockaddr_in")
   addr.sin_family = AF_INET
   addr.sin_port = ffi.C.htons(port)
   ffi.C.inet_aton(ip, addr.sin_addr)
   return ffi.C.bind(fd, ffi.cast("struct sockaddr*",addr), 16)
end

function accept(fd)
	local addr = ffi.new("struct sockaddr_in[1]")
	local len = ffi.new("unsigned int[1]", ffi.sizeof(addr))
	local cfd = ffi.C.accept(fd, ffi.cast("struct sockaddr *",addr), len)
	local val = ffi.cast("unsigned short",ffi.C.ntohs(addr[0].sin_port))
	local port = tonumber(val)
	local ip = ffi.string(ffi.C.inet_ntoa(addr[0].sin_addr))
	return cfd, ip, port
end

function set_nonblock(fd)
	local flag = ffi.new("int[1]",1)
	assert(ffi.C.ioctl(fd, FIONBIO, flag) == 0)
end

function epoll_ctl(pfd, fd, cmd, ...)
	if cmd ~= EPOLL_CTL_DEL then
		local ev = ffi.new("struct epoll_event")
		ev.events = bit.bor(...)
		ev.data.fd = fd
		assert(ffi.C.epoll_ctl(pfd, cmd, fd, ev) == 0)
	else
		assert(ffi.C.epoll_ctl(pfd, cmd, fd, nil) == 0)
	end
end

function timerfd_settime(fd, sec, nsec)
	sec = sec or 0
	nsec = nsec or 0
	local timespec = ffi.new("struct itimerspec")
	timespec.it_value.tv_sec = sec
	timespec.it_value.tv_nsec = nsec
	assert(ffi.C.timerfd_settime(fd, 0, timespec, nil) == 0)
end

local READ_ALL = 1
local READ_LINE = 2
local READ_LEN = 3

local io_mt = {__index = {}}
local MAX_RBUF_LEN = 4096

function io_mt.__index.receive(self, pattern)
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
		local errno = ffi.C.errno
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
				local err = co_yield(YIELD_IO, self.fd)
				if err then return nil,err end
			end
		elseif errno ~= EINTR then
			return nil, ffi.string(ffi.C.strerror(errno))
		end
	end
end

function io_mt.__index.send(self, ...)
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
		local errno = ffi.C.errno
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
			epoll_ctl(g_epoll_fd, self.fd, EPOLL_CTL_MOD, EPOLLET, EPOLLRDHUP, EPOLLIN, EPOLLOUT)
			co_yield(YIELD_IO, self.fd)
			epoll_ctl(g_epoll_fd, self.fd, EPOLL_CTL_MOD, EPOLLET, EPOLLRDHUP, EPOLLIN)
		elseif errno ~= EINTR then
			return false, ffi.string(ffi.C.strerror(errno))
		end
	end
end

local function socket_create(fd, ip, port, gc)
	return setmetatable({fd=fd, ip=ip, port=port}, io_mt)
end

function unescape(s)
	s = string.gsub(s,"+"," ")
	return (string.gsub(s, "%%(%x%x)", function(hex)
		return string.char(tonumber(hex, 16))
	end))
end

-----------------------------------------------------------------------------
-- Parses a url and returns a table with all its parts according to RFC 2396
-- The following grammar describes the names given to the URL parts
-- <url> ::= <scheme>://<authority>/<path>;<params>?<query>#<fragment>
-- <authority> ::= <userinfo>@<host>:<port>
-- <userinfo> ::= <user>[:<password>]
-- <path> :: = {<segment>/}<segment>
-- Input
--   url: uniform resource locator of request
--   default: table with default values for each field
-- Returns
--   table with the following fields, where RFC naming conventions have
--   been preserved:
--     scheme, authority, userinfo, user, password, host, port,
--     path, params, query, fragment
-- Obs:
--   the leading '/' in {/<path>} is considered part of <path>
-----------------------------------------------------------------------------
function parse_url(url, default)
	-- initialize default parameters
	local parsed = {}
	for i,v in pairs(default or parsed) do parsed[i] = v end

	-- get fragment
	url = string.gsub(url, "#(.*)$", function(f)
		parsed.fragment = f
		return ""
	end)

	-- get scheme
	url = string.gsub(url, "^([%w][%w%+%-%.]*)%:",
		function(s) parsed.scheme = s; return "" end)

	-- get authority
	url = string.gsub(url, "^//([^/]*)", function(n)
		parsed.authority = n
		return ""
	end)

	-- get query string
	url = string.gsub(url, "%?(.*)", function(q)
		parsed.query = {}
		for k,v in string.gmatch(q,"([^&=]+)=([^&=]+)") do
			parsed.query[k] = unescape(v)
		end
		return ""
	end)

	-- path is whatever was left
	if url ~= "" then parsed.path = unescape(url) end
	local authority = parsed.authority
	if not authority then return parsed end
	authority = string.gsub(authority,"^([^@]*)@",
		function(u) parsed.userinfo = u; return "" end)
	authority = string.gsub(authority, ":([^:%]]*)$",
		function(p) parsed.port = p; return "" end)
	if authority ~= "" then
		-- IPv6?
		parsed.host = string.match(authority, "^%[(.+)%]$") or authority
	end
	local userinfo = parsed.userinfo
	if not userinfo then return parsed end
	userinfo = string.gsub(userinfo, ":([^:]*)$",
		function(p) parsed.password = p; return "" end)
	parsed.user = userinfo

	return parsed
end

local function receive_headers(sock, headers)
	local line, name, value, err
	headers = headers or {}
	-- get first line
	line, err = sock:receive()
	if err then return nil, err end
	-- headers go until a blank line is found
	while line ~= "" do
		-- get field-name and value
		name, value = string.match(line, "^(.-):%s*(.*)")
		if not (name and value) then return nil, "malformed reponse headers" end
		name = string.lower(name)
		-- get next line (value might be folded)
		line, err = sock:receive()
		if err then return nil, err end
		-- unfold any folded values
		while string.find(line, "^%s") do
			value = value .. line
			line = sock:receive()
			if err then return nil, err end
		end
		-- save pair in table
		if headers[name] then headers[name] = headers[name] .. ", " .. value
		else headers[name] = value end
	end

	return headers
end

function receive_body(sock, headers, chunk_handler)
	local length = tonumber(headers["content-length"])
	if not length or length < 0 then return false, 'invalid content-length' end
	local t = headers["transfer-encoding"]
	if t and t ~= "identity" then
		while true do
			local line, err = sock:receive()
			if err then return false, err end
			-- get chunk size, skip extention
			local size = tonumber(string.gsub(line, ";.*", ""), 16)
			if not size then return false, "invalid chunk size" end
			-- was it the last chunk?
			if size > 0 then
				-- if not, get chunk and skip terminating CRLF
				local chunk, err = sock:receive(size)
				if chunk then sock:receive() else return false, err end
				chunk_handler(chunk)
			else
				-- if it was, read trailers into headers table
				receive_headers(sock, headers)
				break
			end
		end
	elseif length then
		local len
		while true do
			if length > MAX_RBUF_LEN then
				len = MAX_RBUF_LEN
			elseif length == 0 then
				break
			else
				assert(length > 0)
				len = length
			end
			length = length - len
			local chunk, err = sock:receive(len)
			chunk_handler(chunk)
		end
		return true
	end
	return false, 'invalid body'
end

local http_req_mt = {__index={}}
function http_req_mt.__index.read_body(self, sink)
	if self.method ~= 'POST' then return "only support POST" end
	if not self.__priv.body_read then
		receive_body(self.sock, self.headers, sink)
		self.__priv.body_read = true
	end
end

local status_tbl = {
	[200] = "HTTP/1.1 200 OK\r\n";
	[400] = "HTTP/1.1 400 Bad Request\r\n";
	[403] = "HTTP/1.1 403 Forbidden\r\n";
	[404] = "HTTP/1.1 404 Not Found\r\n";
	[500] = "HTTP/1.1 500 Internal Server Error\r\n";
	[501] = "HTTP/1.1 501 Not Implemented\r\n";
	[503] = "HTTP/1.1 503 Service Unavailable\r\n";
}

local http_rsp_mt = {__index={}}

function http_rsp_mt.__index.send_headers(self)
	if not self.__priv.headers_sent then
		local sk = self.sock
		local status = status_tbl[self.status or 200] or status_tbl[500]
		local ret,err = sk:send(status)
		if err then return err end

		-- adjust headers
		if not self.headers["content-length"] then
			self.headers["transfer-encoding"] = "chunked"
		end
		if not self.headers["content-type"] then
			self.headers["content-type"] = "text/plain; charset=utf-8"
		end

		self.headers["server"] = "Lua-Httpd"
		self.headers["date"] = "Thu, 29 Jan 2015 04:56:53 GMT"
		self.headers["cache-control"] = "no-cache, private"
		self.headers["connection"] = "Keep-Alive"

		if self.req.headers["connection"] == "close" then
			self.headers["connection"] = "close"
		end

		local h = "\r\n"
		for f, v in pairs(self.headers) do
			h = f .. ": " .. v .. "\r\n" .. h
		end

		local ret,err = sk:send(h)
		if err then return err end
		self.__priv.headers_sent = true
	end
end

function http_rsp_mt.__index.say(self, str)
	local err = self:send_headers()
	if err then return err end

	local sk = self.sock

	if self.headers["transfer-encoding"] == "chunked" then
		local size = string.format("%X\r\n", string.len(str))
		local ret,err = sk:send(size, str, "\r\n")
		if err then return err end
	else
		local ret,err = sk:send(str)
		if err then return err end
	end
end

local function http_req_new(method, url, headers, sock)
	return setmetatable({__priv = {},
		method = method, url = url,
		headers = headers, sock = sock}, http_req_mt)
end

local function http_rsp_new(req, sock)
	return setmetatable({__priv = {}, headers = {}, sock = sock, req = req}, http_rsp_mt)
end

local g_listen_sk_tbl = {}
local g_http_cfg
function http_conf(cf)
	g_http_cfg = cf
	local srv_tbl = {}
	for _,srv in ipairs(g_http_cfg) do
		for ip,port in string.gmatch(srv.listen, "([%d%.%*]+):(%d+)") do
			if not srv_tbl[port] then srv_tbl[port] = {} end
			if ip == '*' then
				srv_tbl[port] = {['*']=1}
			elseif not srv_tbl[port]['*'] then
				srv_tbl[port][ip] = 1
			end
		end
	end
	local option = ffi.new("int[1]", 1)
	for port,ip_set in pairs(srv_tbl) do
		for ip,_ in pairs(ip_set) do
			local sk = ffi.C.socket(AF_INET, SOCKET_STREAM, 0)
			assert(ffi.C.setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, ffi.cast("void*",option), ffi.sizeof("int")) == 0)
			assert(bind(sk, ip, tonumber(port)) == 0)
			assert(ffi.C.listen(sk, 100) == 0)
			set_nonblock(sk)
			g_listen_sk_tbl[sk] = socket_create(sk, ip, port)
			g_listen_sk_tbl[sk].listen = ip .. ':' .. port
		end
	end
end

local function do_servlet(req, rsp)
	local sk = req.sock
	local target_srv
	local host = req.headers["host"]
	for _,srv in ipairs(g_http_cfg) do
		if string.find(srv.listen, sk.listen, 1, true) then
			for _,h in pairs(srv.host) do
				if h == host then
					target_srv = srv
					break
				elseif h:find('~',1,true) then
					if string.find(host, h:sub(2)) then
						target_srv = srv
						break
					end
				end
			end
			if not target_srv then target_srv = srv end
		end
	end

	local servlet
	if target_srv then
		local longest_n = 0
		local path = req.url.path
		local idx
		local match_done = false
		for i,slcf in ipairs(target_srv.servlet) do
			local modifier,pat = slcf[1],slcf[2]
			if modifier == "=" then
				if path == pat then
					idx = i
					match_done = true
					break
				end
			elseif modifier == "^" or modifier == "^~" then
				local s,e = string.find(path, pat, 1, true)
				if s and e > longest_n then
					longest_n, idx, match_done = e, i, (modifier == "^~")
				end
			end
		end

		if match_done == true then
			servlet = target_srv.servlet[idx]
		else
			for i,slcf in ipairs(target_srv.servlet) do
				local modifier,pat = slcf[1],slcf[2]
				if modifier == "~" then
					if string.find(path, pat) then
						idx = i
						break
					end
				elseif modifier == "~*" then
					if string.find(string.lower(path), string.lower(pat)) then
						idx = i
						break
					end
				elseif modifier == "f"  then
					if pat(req) then
						idx = i
						break
					end
				end
			end
			if idx then servlet = target_srv.servlet[idx] end
		end
	end

	if servlet then
		local fn = servlet[3]
		local extra = servlet[4]
		local err
		if type(fn) == 'string' then
			fn = require(fn)
			assert(fn)
			err = fn.service(req,rsp,target_srv,extra)
		elseif type(fn) == 'function' then
			err = fn(req,rsp,target_srv,extra)
		end
		if not err then
			if rsp.headers["transfer-encoding"] == "chunked" then
				local ret
				ret,err = rsp.sock:send("0\r\n\r\n")
			end
		end
		if err then
			print(err)
			return false
		end
	else
		print "no servlet"
	end
end

local function http_request_handler(sock)
	while true do
		local line,err = sock:receive()
		if err then print(err); break end
		local method,url,ver = string.match(line, "(.*) (.*) HTTP/(%d%.%d)")
		url = parse_url(url)
		local headers = receive_headers(sock)
		local req = http_req_new(method, url, headers, sock)
		local rsp = http_rsp_new(req, sock)
		local success = do_servlet(req, rsp)
		if (success == false) or headers["connection"] == "close" then
			break
		end
	end
	return YIELD_EXIT
end

function do_all_listen_sk(f)
	for sk,sock in pairs(g_listen_sk_tbl) do
		f(sk,sock)
	end
end

--#--

local rt = ffi.load("rt")
local g_timers = {}
local timer_mt = {
	__index = {
		cancel = function(self)
			self.canceled = true
		end
	}
}

function timer_lt(a,b)
	if a.tv_sec < b.tv_sec then return true end
	if a.tv_sec == b.tv_sec and a.tv_nsec < b.tv_nsec then
		return true
	end
	return false
end

function add_timer(fn, sec)
	assert(sec > 0)
	local nsec = (sec%1) * 1000 * 1000 * 1000
	sec = math.floor(sec)

	local tv = ffi.new("struct timespec")
	assert(rt.clock_gettime(CLOCK_MONOTONIC_RAW, tv) == 0)
	local timer = setmetatable({
		tv_sec = tv.tv_sec + sec,
		tv_nsec = tv.tv_nsec + nsec,
		fn = fn
	}, timer_mt)

	table.insert(g_timers, timer)
	table.sort(g_timers, timer_lt)

	if g_timers[1] == timer then
		timerfd_settime(g_timer_fd, sec, nsec)
	end

	return timer
end

local function process_all_timers()
	local ntimer = #g_timers
	if ntimer == 0 then return 0 end

	local tv = ffi.new("struct timespec")
	assert(rt.clock_gettime(CLOCK_MONOTONIC_RAW, tv) == 0)
	local timers = {}

	for i=1,ntimer do
		local t = g_timers[1]
		if timer_lt(t, tv) then
			if not t.canceled then table.insert(timers, t) end
			table.remove(g_timers, 1)
		else
			break
		end
	end

	for _,t in ipairs(timers) do
		t.fn()
	end

	return #timers
end

local function get_next_interval()
	local t = g_timers[1]
	if not t then return nil end

	local tv = ffi.new("struct timespec")
	assert(rt.clock_gettime(CLOCK_MONOTONIC_RAW, tv) == 0)
	assert(timer_lt(tv, t))

	local sec = t.tv_sec - tv.tv_sec
	if  tv.tv_nsec > t.tv_nsec then
		sec = sec - 1
		nsec = t.tv_nsec + 1000*1000*1000 - tv.tv_nsec
	else
		nsec = t.tv_nsec - tv.tv_nsec
	end

	return sec, nsec
end

--#--

local co_wait_io_list = {}
local co_idle_list = setmetatable({},{__mode="v"})
local co_info = {}

function co_sleep(sec)
	local co = coroutine.running()
	assert(co)
	add_timer(function() co_resume(co) end, sec)
	co_yield(YIELD_SLEEP)
end

function co_kill(co, parent)
	if co_info[co] then
		parent = parent or coroutine.running()
		if co_info[co].parent ~= parent then
			return false,'not direct child'
		end

		for child_co,_ in pairs(co_info[co].childs) do
			co_kill(child_co, co)
		end

		co_info[co] = nil
	end
	return true
end

function co_resume(co, ...)
	local cinfo = co_info[co]
	if not cinfo then
		print"coroutine already killed"
		return false,"coroutine already killed"
	end

	local r,flag,data = coroutine.resume(co, ...)
	if coroutine.status(co) == "dead" then
		-- call gc first
		local gc = cinfo.gc
		if gc then gc() end

		-- tell parent
		local parent = cinfo.parent
		if parent then
			co_info[parent].childs[co] = nil
			if cinfo.wait_by_parent then
				co_resume(parent,r,flag,data)
			else
				co_info[parent].exit_childs[co] = {r,flag,data}
			end
		end

		-- kill all active childs
		for child_co,_ in pairs(cinfo.childs) do
			co_kill(child_co)
		end

		co_info[co] = nil
	end

	return r,flag,data
end

function co_yield(flag, fd, ...)
	if not flag then flag = YIELD_IDLE end

	local co = coroutine.running()
	assert(co)

	if flag == YIELD_IO then
		if not co_wait_io_list[fd] then
			co_wait_io_list[fd] = setmetatable({},{__mode="v"})
		end
		table.insert(co_wait_io_list[fd], co)
	elseif flag == YIELD_IDLE then
		table.insert(co_idle_list, co)
	end

	return coroutine.yield(flag, fd, ...)
end

function co_spawn(fn, gc)
	local parent = coroutine.running()
	local co = coroutine.create(fn)
	co_info[co] = {parent=parent, gc=gc,
		childs=setmetatable({},{__mode="k"}),
		exit_childs=setmetatable({},{__mode="k"})}
	if parent then co_info[parent].childs[co] = 1 end
	co_resume(co)
	return co
end

function co_wait(...)
	local parent = coroutine.running()
	assert(parent)
	local n = select('#',...)
	for i=1,n do
		local co = select(i,...)
		local d = co_info[parent].exit_childs[co]
		if d then
			co_info[parent].exit_childs[co] = nil
			return unpack(d)
		elseif not co_info[co] then
			return false,'#' .. i .. ': ' .. tostring(co) .. ' not exist'
		elseif co_info[co].parent ~= parent then
			return false,'#' .. i .. ': ' .. tostring(co) .. ' not your child'
		end
	end
	for i=1,n do
		local co = select(i,...)
		co_info[co].wait_by_parent = true
	end
	local r,flag,data = co_yield(YIELD_WAIT)
	for i=1,n do
		local co = select(i,...)
		if co_info[co] then
			co_info[co].wait_by_parent = false
		end
	end
	return r,flag,data
end

--#--

local g_args = {...}
local conffile = g_args[1] or "httpd_conf.lua"
assert(loadfile(conffile))()

local MAX_EPOLL_EVENT = 128
local ev_set = ffi.new("struct epoll_event[?]", MAX_EPOLL_EVENT)

local mask = ffi.new("sigset_t")
ffi.C.sigemptyset(mask)
ffi.C.sigaddset(mask, SIGCHLD)
ffi.C.sigprocmask(SIG_BLOCK, mask, NULL)
local xfd = ffi.C.signalfd(-1, mask, 0)

local master_epoll_fd = ffi.C.epoll_create(20000)
epoll_ctl(master_epoll_fd, xfd, EPOLL_CTL_ADD, EPOLLIN)

local MAX_CONN_PER_PROC = 2
local child_n = 1
local efds = {}
for i=1,child_n do
	local efd = ffi.C.eventfd(0, 0)
	assert(efd > 0)
	table.insert(efds, efd)
	local pid = ffi.C.fork()
	if pid == 0 then
		print("child pid=" .. ffi.C.getpid() .. " enter")

		local connections = 0
		ffi.C.close(master_epoll_fd)
		ffi.C.close(xfd)
		g_epoll_fd = ffi.C.epoll_create(20000)
		local wait_listen_sk = false

		-- add event fd
		epoll_ctl(g_epoll_fd, efd, EPOLL_CTL_ADD, EPOLLIN, EPOLLET)

		-- add timer fd
		g_timer_fd = ffi.C.timerfd_create(CLOCK_MONOTONIC, 0)
		assert(g_timer_fd > 0)
		epoll_ctl(g_epoll_fd, g_timer_fd, EPOLL_CTL_ADD, EPOLLIN)

		while true do
			-- listen all server sockets
			if (not wait_listen_sk) and connections < MAX_CONN_PER_PROC then
				print("child pid=" .. ffi.C.getpid() .. " listen sk")
				do_all_listen_sk(function(sk) epoll_ctl(g_epoll_fd, sk, EPOLL_CTL_ADD, EPOLLIN) end)
				wait_listen_sk = true
			end

			-- wakeup idle threads
			local wait_timeout = -1
			for i=1,#co_idle_list do
				co_resume(co_idle_list[1])
				table.remove(co_idle_list,1)
			end
			if #co_idle_list > 0 then wait_timeout = 0 end

			print("child pid=" .. ffi.C.getpid() .. " epoll_wait enter...")
			local nevents = ffi.C.epoll_wait(g_epoll_fd, ev_set, MAX_EPOLL_EVENT, wait_timeout)
			print("child pid=" .. ffi.C.getpid() .. " epoll_wait exit...")

			for ev_idx=0,nevents-1 do
				local fd = ev_set[ev_idx].data.fd
				if g_listen_sk_tbl[fd] then
					print("child pid=" .. ffi.C.getpid() .. " accept enter...")
					local cfd,ip,port = accept(fd)
					print("child pid=" .. ffi.C.getpid() .. " accept exit...")
					if cfd > 0 then
						print("child pid=" .. ffi.C.getpid() .. " get new connection, cfd=" .. cfd .. ", port=" .. port)
						set_nonblock(cfd)
						epoll_ctl(g_epoll_fd, cfd, EPOLL_CTL_ADD, EPOLLIN, EPOLLRDHUP, EPOLLET)
						connections = connections + 1
						if connections >= MAX_CONN_PER_PROC then
							print("child pid=" .. ffi.C.getpid() .. " unlisten sk")
							do_all_listen_sk(function(sk) epoll_ctl(g_epoll_fd, sk, EPOLL_CTL_DEL) end)
							wait_listen_sk = false
						end

						local sock = socket_create(cfd, ip, port)
						sock.listen = g_listen_sk_tbl[fd].listen
						co_spawn(
							function()
								local r1,r2 = pcall(function() return http_request_handler(sock) end)
								if r1 == false then print(r2); os.exit(1) end
								return r2
							end,
							function()
								print("child pid=" .. ffi.C.getpid() .. " remove connection, cfd=" .. cfd)
								ffi.C.close(cfd)
								connections = connections - 1
							end
						)
					else
						print("child pid=" .. ffi.C.getpid() .. " accept error, ignore")
					end
				elseif fd == g_timer_fd then
					print("child pid=" .. ffi.C.getpid() .. " timer fired")
					timerfd_settime(g_timer_fd, 0, 0)
					while process_all_timers() > 0 do end
					local sec,nsec = get_next_interval()
					if sec then timerfd_settime(g_timer_fd, sec, nsec) end
				elseif fd == efd then
					local v = ffi.new("eventfd_t[1]")
					ffi.C.eventfd_read(efd, v)
					v = tonumber(v[0])
					print("child pid=" .. ffi.C.getpid() .. " event fd fired, v=" .. v)
				else
					if bit.band(ev_set[ev_idx].events, EPOLLRDHUP) ~= 0 then
						print("EPOLLRDHUP happens, close fd=" .. fd)
						ffi.C.close(fd)
					end

					local co_list = co_wait_io_list[fd]
					if co_list then
						for i=1,#co_list do
							co_resume(co_list[1])
							table.remove(co_list,1)
						end
					end
				end
			end
		end
		print("child pid=" .. ffi.C.getpid() .. " exit")
		os.exit(0)
	end
end

-- local v = ffi.new("eventfd_t", 12)
-- ffi.C.eventfd_write(efds[1], v)

do_all_listen_sk(function(sk) ffi.C.close(sk) end)
print("parent wait " .. child_n .. " child")
while child_n > 0 do
	assert(ffi.C.epoll_wait(master_epoll_fd, ev_set, MAX_EPOLL_EVENT, -1) == 1)
	assert(ev_set[0].data.fd == xfd)
	local siginfo = ffi.new("struct signalfd_siginfo")
	assert(ffi.C.read(xfd, siginfo, ffi.sizeof("struct signalfd_siginfo")) == ffi.sizeof("struct signalfd_siginfo"))
	print ("> child exit with pid=" .. siginfo.ssi_pid .. ", status=" .. siginfo.ssi_status)
	child_n = child_n - 1
end
print "parent exit"
