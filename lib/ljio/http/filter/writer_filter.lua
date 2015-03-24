-- Copyright (C) Jinhua Luo

local http_time = require("ljio.core.utils").http_time
local constants = require("ljio.http.constants")
local tinsert = table.insert

local M = {}

local postpone_output = 1460
local eol = "\r\n"
local sep = ": "

function M.header_filter(rsp)
	local lcf = rsp.req.lcf or rsp.req.srvcf

	local status = constants.status_tbl[rsp.status or 200]
	assert(status)
	local ret,err = rsp.sock:send(status)
	if err then return nil,err end

	if rsp.status ~= 304 and rsp.headers["content-type"] == nil then
		rsp.headers["content-type"] = lcf.default_type
	end

	rsp.headers["server"] = "luajit.io"

	rsp.headers["date"] = http_time()
	if rsp.headers["cache-control"] == nil then
		rsp.headers["cache-control"] = "no-cache, no-store, private, must-revalidation"
	end
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
	if rsp.buffers_bytes and rsp.buffers_bytes > 0 then
		local ret,err = rsp.sock:send(rsp.buffers)

		rsp.bufpool:put(rsp.buffers)
		rsp.buffers = nil
		rsp.buffers_bytes = 0

		if err then return nil,err end
		rsp.body_sent = true
	end

	return true
end

local function merge_table(to, from)
	local idx = #to
	for i, v in ipairs(from) do
		to[idx + 1] = v
		idx = idx + 1
	end
end

function M.body_filter(rsp, ...)
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
			if rsp.buffers == nil then
				rsp.buffers = buf
				rsp.buffers_bytes = buf.size
			else
				merge_table(rsp.buffers, buf)
				rsp.buffers_bytes = rsp.buffers_bytes + buf.size
				rsp.bufpool:put(buf)
			end
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
