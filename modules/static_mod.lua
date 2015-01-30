local ffi = require"ffi"

ffi.cdef[[
typedef int ssize_t;
typedef unsigned int size_t;
ssize_t sendfile(int out_fd, int in_fd, void *offset, size_t count);
int open(const char *pathname, int flags);
extern int setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen);
int close(int fd);
]]

local mime_types = {
	["html"] = "text/html",
	["htm"] = "text/html",
	["shtml"] = "text/html",
	["css"] = "text/css",
	["xml"] = "text/xml",
	["rss"] = "text/xml",
	["gif"] = "image/gif",
	["jpeg"] = "image/jpeg",
	["jpg"] = "image/jpeg",
	["js"] = "application/x-javascript",
}

local function service(req, rsp, cf)
	local option = ffi.new("int[1]", 1)
	assert(ffi.C.setsockopt(rsp.sock.fd, IPPROTO_TCP, TCP_CORK, ffi.cast("void*",option), ffi.sizeof("int")) == 0)

	local ext = string.match(req.url.path, "%.([^%.]+)$")
	rsp.headers["content-type"] = mime_types[ext] or "application/octet-stream"
	local path = (cf.root or ".") .. '/' .. req.url.path
	local f = io.open(path)
	assert(f)
	local flen = f:seek('end')
	f:close()
	rsp.headers["content-length"] = flen
	rsp:send_headers()

	local fd = ffi.C.open(path, 0)
	assert(fd)
	local err
	while true do
		local len = ffi.C.sendfile(rsp.sock.fd, fd, nil, flen)
		local errno = ffi.C.errno

		if len > 0 then flen = flen - len end
		if flen == 0 then break end

		if len == 0 then
			-- done? socket broken?
			err = "sendfile: socket broekn"
			break
		elseif errno == EAGAIN then
			epoll_ctl(g_epoll_fd, rsp.sock.fd, EPOLL_CTL_MOD, EPOLLIN, EPOLLOUT)
			coroutine.yield(YIELD_IO, rsp.sock.fd)
			epoll_ctl(g_epoll_fd, rsp.sock.fd, EPOLL_CTL_MOD, EPOLLIN)
		elseif errno ~= EINTR then
			err = ffi.string(ffi.C.strerror(errno))
			break
		end
	end
	assert(ffi.C.close(fd) == 0)
	if err then return err end
end

return {service = service}
