local http_time = require("core.utils").http_time
local tinsert = table.insert

local M = {}

local status_tbl = {
	[200] = "HTTP/1.1 200 OK\r\n";
	[302] = "HTTP/1.1 302 Found\r\n";
	[400] = "HTTP/1.1 400 Bad Request\r\n";
	[403] = "HTTP/1.1 403 Forbidden\r\n";
	[404] = "HTTP/1.1 404 Not Found\r\n";
	[500] = "HTTP/1.1 500 Internal Server Error\r\n";
	[501] = "HTTP/1.1 501 Not Implemented\r\n";
	[503] = "HTTP/1.1 503 Service Unavailable\r\n";
}

local postpone_output = 1460
local eol = "\r\n"
local sep = ": "

function M.header_filter(rsp)
	local lcf = rsp.req.lcf or rsp.req.srvcf

	local status = status_tbl[rsp.status or 200]
	assert(status)
	local ret,err = rsp.sock:send(status)
	if err then return nil,err end

	if rsp.headers["content-type"] == nil then
		rsp.headers["content-type"] = lcf.default_type
	end

	rsp.headers["server"] = "luajit.io"

	rsp.headers["date"] = http_time()
	rsp.headers["cache-control"] = "no-cache, private"
	rsp.headers["connection"] = "Keep-Alive"

	if rsp.req.headers["connection"] == "close" then
		rsp.headers["connection"] = "close"
	end

	local buf = rsp.bufpool:get()
	for f,v in pairs(rsp.headers) do
		buf:append(f, sep, v, eol)
	end
	buf:append(eol)

	local ret,err = rsp.sock:send(buf)
	rsp.bufpool:put(buf)
	if err then return nil,err end
	rsp.headers_sent = true

	return true
end

local function flush_body(rsp)
	if rsp.buffers_bytes > 0 then
		rsp.buffers[rsp.buffers_idx] = nil
		local ret,err = rsp.sock:send(rsp.buffers)

		for i=1,rsp.buffers_idx-1 do
			rsp.bufpool:put(rsp.buffers[i])
			rsp.buffers[i] = nil
		end

		rsp.buffers_idx = 1
		rsp.buffers_bytes = 0

		if err then return nil,err end
		rsp.body_sent = true
	end

	return true
end

function M.body_filter(rsp, ...)
	if rsp.buffers == nil then
		rsp.buffers = {}
		rsp.buffers_bytes = 0
		rsp.buffers_idx = 1
	end

	for i=1,select("#", ...) do
		local buf = select(i, ...)
		local eof = buf.eof
		if buf.is_file then
			local ret,err = flush_body(rsp)
			if err then return ret,err end
			local ret,err = rsp.sock:sendfile(buf.path, buf.offset, buf.size)
			if err then return ret,err end
			rsp.bufpool:put(buf)
		elseif buf.size > 0 then
			rsp.buffers[rsp.buffers_idx] = buf
			rsp.buffers_bytes = rsp.buffers_bytes + buf.size
			rsp.buffers_idx = rsp.buffers_idx + 1
		end

		if buf.flush or eof or rsp.buffers_bytes >= postpone_output then
			local ret,err = flush_body(rsp)
			if err then return ret,err end
		end

		if eof then
			rsp.eof = true
			break
		end
	end

	return true
end

return M
