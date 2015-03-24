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
	local buf = rsp.bufpool:get()
	local status = constants.status_tbl[rsp.status or 200]
	buf:append(status)

	if rsp.status ~= 304 and rsp.headers["content-type"] == nil then
		buf:append("content-type: ", lcf.default_type, "\r\n")
	end

	buf:append("server: luajit.io\r\n")

	buf:append("date: ", http_time(), "\r\n")
	if rsp.headers["cache-control"] == nil then
		buf:append("cache-control: no-cache, no-store, private, must-revalidation\r\n")
	end

	if rsp.req.headers["connection"] == "close" then
		buf:append("connection: close\r\n")
	else
		buf:append("connection: keep-alive\r\n")
	end

	for f,v in pairs(rsp.headers) do
		buf:append(f, sep, v, eol)
	end

	buf:append(eol)

	rsp.buffers = buf
	rsp.headers_sent = true

	return true
end

local function flush_body(rsp)
	if rsp.buffers and rsp.buffers.size > 0 then
		local ret,err = rsp.sock:send(rsp.buffers)

		rsp.bufpool:put(rsp.buffers)
		rsp.buffers = nil

		if err then return nil,err end
		rsp.body_sent = true
	end

	return true
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
			else
				rsp.buffers:append(unpack(buf))
				rsp.bufpool:put(buf)
			end
		end

		if buf.flush or eof or rsp.buffers.size >= postpone_output then
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
