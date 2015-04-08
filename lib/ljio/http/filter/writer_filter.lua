-- Copyright (C) Jinhua Luo

local http_time = require("ljio.core.utils").http_time
local buf_get = require("ljio.http.buf").get
local constants = require("ljio.http.constants")

local ipairs = ipairs
local tinsert = table.insert

local M = {}

local postpone_output = 1460

function M.header_filter(rsp)
	local buf = buf_get()
	tinsert(buf, constants.status_tbl[rsp.status])
	tinsert(buf, "server: luajit.io\r\n")

	if rsp.status ~= 304 and rsp.headers["content-type"] == nil then
		local lcf = rsp.req.lcf or rsp.req.srvcf
		tinsert(buf, "content-type: ")
		tinsert(buf, lcf.default_type)
		tinsert(buf, "\r\n")
	end

	tinsert(buf, "date: ")
	tinsert(buf, http_time())
	tinsert(buf, "\r\n")

	if rsp.req.headers["connection"] == "close" then
		tinsert(buf, "connection: close\r\n")
	else
		tinsert(buf, "connection: keep-alive\r\n")
	end

	for _, key in ipairs(rsp.headers) do
		if rsp.headers[key] then
			tinsert(buf, key)
			tinsert(buf, ": ")
			tinsert(buf, rsp.headers[key])
			tinsert(buf, "\r\n")
		end
	end

	tinsert(buf, "\r\n")

	buf.size = 0
	for i, v in ipairs(buf) do
		buf.size = buf.size + #v
	end

	rsp.buf = buf

	rsp.headers_sent = true

	return true
end

local function flush_body(rsp)
	if rsp.buf.size > 0 then
		local ret,err = rsp.sock:send(rsp.buf)
		if rsp.eof then
			rsp.buf:put()
			rsp.buf = nil
		else
			rsp.buf.size = 0
			for i, v in ipairs(rsp.buf) do
				rsp.buf[i] = nil
			end
		end
		rsp.body_sent = true
		if err then return nil,err end
	end
	return true
end

function M.body_filter(rsp, data)
	local typ = type(data)
	if typ == "string" then
		rsp.buf.size = rsp.buf.size + #data
		tinsert(rsp.buf, data)
		if rsp.buf.size >= postpone_output then
			local ret,err = flush_body(rsp)
			if err then return ret,err end
		end
	elseif typ == "table" then
		local ret,err = flush_body(rsp)
		if err then return ret,err end
		local ret,err = rsp.sock:sendfile(data.path, data.offset, data.size)
		if err then return ret,err end
	elseif data == constants.flush or data == constants.eof then
		if data == constants.eof then
			rsp.eof = true
		end
		local ret,err = flush_body(rsp)
		if err then return ret,err end
	end

	return true
end

return M
