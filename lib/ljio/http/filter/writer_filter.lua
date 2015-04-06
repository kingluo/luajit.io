-- Copyright (C) Jinhua Luo

local http_time = require("ljio.core.utils").http_time
local constants = require("ljio.http.constants")
local array_append = require("ljio.http.buf").append
local array_truncate = require("ljio.http.buf").truncate
local calc_size = require("ljio.http.buf").calc_size

local ipairs = ipairs
local tinsert = table.insert

local M = {}

local postpone_output = 1460

function M.header_filter(rsp)
	local status = constants.status_tbl[rsp.status]
	local buf = {status, "server: luajit.io\r\n", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil}

	local headers = rsp.headers

	if rsp.status ~= 304 and headers["content-type"] == nil then
		local lcf = rsp.req.lcf or rsp.req.srvcf
		array_append(buf, "content-type: ", lcf.default_type, "\r\n")
	end

	tinsert(buf, "date: " .. http_time() .. "\r\n")

	if rsp.req.headers["connection"] == "close" then
		tinsert(buf, "connection: close\r\n")
	else
		tinsert(buf, "connection: keep-alive\r\n")
	end

	for _, key in ipairs(headers) do
		if headers[key] then
			array_append(buf, key, ": ", headers[key], "\r\n")
		end
	end

	tinsert(buf, "\r\n")

	calc_size(buf)
	rsp.buf = buf
	rsp.headers_sent = true

	return true
end

local function flush_body(rsp)
	if rsp.buf and rsp.buf.size > 0 then
		local ret,err = rsp.sock:send(rsp.buf)
		array_truncate(rsp.buf)
		rsp.buf.size = 0
		rsp.body_sent = true
		if err then return nil,err end
	end

	return true
end

function M.body_filter(rsp, buf)
	if buf.eof then
		rsp.eof = true
	end

	if buf.is_file then
		local ret,err = flush_body(rsp)
		if err then return ret,err end
		local ret,err = rsp.sock:sendfile(buf.path, buf.offset, buf.size)
		if err then return ret,err end
	elseif buf.size > 0 then
		tinsert(rsp.buf, buf)
		rsp.buf.size = rsp.buf.size + buf.size
	end

	if buf.flush or buf.eof or (rsp.buf and rsp.buf.size >= postpone_output) then
		local ret,err = flush_body(rsp)
		if err then return ret,err end
	end

	return true
end

return M
