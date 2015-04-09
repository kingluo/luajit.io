-- Copyright (C) Jinhua Luo

local http_time = require("ljio.core.utils").http_time
local buf_get = require("ljio.http.buf").get
local constants = require("ljio.http.constants")

local ipairs = ipairs
local tinsert = table.insert

local M = {}

local postpone_output = 1460

local server = "Server: luajit.io\r\n"
local s_server = #server
local ct = "content-type: "
local s_ct = #ct
local eol = "\r\n"
local s_eol = #eol
local date = "date: "
local s_date = #date
local conn_close = "connection: close\r\n"
local s_conn_close = #conn_close
local conn_keepalive = "connection: keep-alive\r\n"
local s_conn_keepalive = #conn_keepalive
local colon = ": "
local s_colon = #colon

local function copy_headers(rsp, buf, i, j)
	i = i or 1
	j = j or #rsp.headers
	if i <= j then
		local key = rsp.headers[i]
		local v = rsp.headers[key]
		if v then
			tinsert(buf, key)
			tinsert(buf, colon)
			tinsert(buf, v)
			tinsert(buf, eol)
			buf.size = buf.size + #key + s_colon + #v + s_eol
		end
		if i < j then
			return copy_headers(rsp, buf, i + 1, j)
		end
	end
end

function M.header_filter(rsp)
	local status = constants.status_tbl[rsp.status]
	local buf = {size = 0; status, server, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil}
	--local buf = buf_get()
	--buf.size = 0
	--tinsert(buf, status)
	--tinsert(buf, server) 
	buf.size = buf.size + #status + s_server

	if rsp.status ~= 304 and rsp.headers["content-type"] == nil then
		local lcf = rsp.req.lcf or rsp.req.srvcf
		tinsert(buf, ct)
		tinsert(buf, lcf.default_type)
		tinsert(buf, eol)
		buf.size = buf.size + s_ct + #lcf.default_type + s_eol
	end

	tinsert(buf, date)
	local ht = http_time()
	tinsert(buf, ht)
	tinsert(buf, eol)
	buf.size = buf.size + s_date + #ht + s_eol

	if rsp.req.headers["connection"] == "close" then
		tinsert(buf, conn_close)
		buf.size = buf.size + s_conn_close
	else
		tinsert(buf, conn_keepalive)
		buf.size = buf.size + s_conn_keepalive
	end

	copy_headers(rsp, buf)

	tinsert(buf, eol)
	buf.size = buf.size + s_eol

	rsp.buf = buf

	rsp.headers_sent = true

	return true
end

local function flush_body(rsp)
	if rsp.buf.size > 0 then
		local ret,err = rsp.sock:send(rsp.buf)
		rsp.buf = rsp.eof and nil or {size = 0; nil, nil, nil}
		--if rsp.eof then
		--	rsp.buf:put()
		--	rsp.buf = nil
		--else
		--	rsp.buf:clear()
		--	rsp.buf.size = 0
		--end
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
