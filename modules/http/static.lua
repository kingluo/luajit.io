local ffi = require"ffi"
local C = require"cdef"
local epoll = require"core.epoll"

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

local function service(req, rsp, cf)
	--local option = ffi.new("int[1]", 1)
	--assert(C.setsockopt(rsp.sock.fd, C.IPPROTO_TCP, C.TCP_CORK, ffi.cast("void*",option), ffi.sizeof("int")) == 0)

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

	local fd = C.open(fpath, 0)
	assert(fd)
	local err
	while true do
		local len = C.sendfile(rsp.sock.fd, fd, nil, flen)
		local errno = ffi.errno()

		if len > 0 then flen = flen - len end
		if flen == 0 then break end

		if len == 0 then
			err = "sendfile: socket broekn"
			break
		elseif errno == C.EAGAIN then
			epoll.add_event(rsp.sock.ev, C.EPOLLOUT)
			rsp.sock:yield(YIELD_W)
			epoll.del_event(rsp.sock.ev, C.EPOLLOUT)
		elseif errno ~= C.EINTR then
			err = ffi.string(C.strerror(errno))
			break
		end
	end
	assert(C.close(fd) == 0)
	if err then return nil,err end
end

return service
