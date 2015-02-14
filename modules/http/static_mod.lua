local ffi = require"ffi"
local ep = require"core.epoll_mod"

ffi.cdef[[
typedef int ssize_t;
typedef unsigned int size_t;
ssize_t sendfile(int out_fd, int in_fd, void *offset, size_t count);
int open(const char *pathname, int flags);
extern int setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen);
int close(int fd);
]]

local mime_types = {
	["txt"] = "text/plain",
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

local IPPROTO_TCP = 6
local TCP_CORK = 3

local function service(req, rsp, cf)
	--local option = ffi.new("int[1]", 1)
	--assert(ffi.C.setsockopt(rsp.sock.fd, IPPROTO_TCP, TCP_CORK, ffi.cast("void*",option), ffi.sizeof("int")) == 0)

	local path = req.url:path()
	local ext = string.match(path, "%.([^%.]+)$")
	rsp.headers["content-type"] = mime_types[ext] or "application/octet-stream"
	local fpath = (cf.root or ".") .. '/' .. path
	local f = io.open(fpath)
	assert(f)
	local flen = f:seek('end')
	f:close()
	rsp.headers["content-length"] = flen
	rsp:send_headers()

	local fd = ffi.C.open(fpath, 0)
	assert(fd)
	local err
	while true do
		local len = ffi.C.sendfile(rsp.sock.fd, fd, nil, flen)
		local errno = ffi.errno()

		if len > 0 then flen = flen - len end
		if flen == 0 then break end

		if len == 0 then
			err = "sendfile: socket broekn"
			break
		elseif errno == EAGAIN then
			ep.add_event(rsp.sock.ev, ep.EPOLLOUT)
			rsp.sock:yield(YIELD_W)
			ep.del_event(rsp.sock.ev, ep.EPOLLOUT)
		elseif errno ~= EINTR then
			err = ffi.string(ffi.C.strerror(errno))
			break
		end
	end
	assert(ffi.C.close(fd) == 0)
	if err then return nil,err end
end

return service
