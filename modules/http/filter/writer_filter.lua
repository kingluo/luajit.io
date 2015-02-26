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

function M.header_filter(rsp)
	local lcf = rsp.req.lcf or rsp.req.srvcf

	local status = status_tbl[rsp.status or 200] or status_tbl[500]
	local ret,err = rsp.sock:send(status)
	if err then return nil,err end

	if not rsp.headers["content-type"] then
		rsp.headers["content-type"] = lcf.default_type
	end

	rsp.headers["server"] = "luajit.io"

	rsp.headers["date"] = http_time()
	rsp.headers["cache-control"] = "no-cache, private"
	rsp.headers["connection"] = "Keep-Alive"

	if rsp.req.headers["connection"] == "close" then
		rsp.headers["connection"] = "close"
	end

	rsp.output_buf = {}
	rsp.output_buf_bytes = 0
	rsp.output_buf_idx = 1

	local tbl = rsp.output_buf
	local eol = "\r\n"
	local sep = ": "
	for f, v in pairs(rsp.headers) do
		tinsert(tbl, f)
		tinsert(tbl, sep)
		tinsert(tbl, v)
		tinsert(tbl, eol)
	end
	tinsert(tbl, eol)

	local ret,err = rsp.sock:send(tbl)
	if err then return nil,err end
	rsp.headers_sent = true

	return true
end

local function flush_body(rsp)
	if rsp.output_buf_bytes > 0 then
		rsp.output_buf[rsp.output_buf_idx] = nil
		rsp.output_buf_idx = 1
		rsp.output_buf_bytes = 0
		local ret,err = rsp.sock:send(rsp.output_buf)
		if err then return nil,err end
		rsp.body_sent = true
	end

	return true
end

function M.body_filter(rsp, ...)
	assert(rsp.output_buf)

	for i=1,select("#", ...) do
		local buf = select(i, ...)
		if buf.is_file then
			local ret,err = flush_body(rsp)
			if err then return ret,err end
			local ret,err = rsp.sock:sendfile(buf.path, buf.offset, buf.size)
			if err then return ret,err end
		elseif buf.size > 0 then
			rsp.output_buf[rsp.output_buf_idx] = buf
			rsp.output_buf_bytes = rsp.output_buf_bytes + buf.size
			rsp.output_buf_idx = rsp.output_buf_idx + 1
		end

		if buf.flush or buf.eof or rsp.output_buf_bytes >= postpone_output then
			local ret,err = flush_body(rsp)
			if err then return ret,err end
		end

		if buf.eof then
			rsp.eof = true
			break
		end
	end

	return true
end

return M
