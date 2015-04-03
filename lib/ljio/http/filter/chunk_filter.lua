-- Copyright (C) Jinhua Luo

local M = {}

local tinsert = table.insert
local strformat = string.format

local eof = "0\r\n\r\n"
local eol = "\r\n"

function M.header_filter(rsp)
	local status = rsp.status
	if status == 304 or status == 204 or status < 200 or rsp.req.method == "HEAD" then
		return M.next_header_filter(rsp)
	end

	if not rsp.headers["content-length"] then
		rsp.headers["transfer-encoding"] = "chunked"
		rsp.chunked = true
	end
	return M.next_header_filter(rsp)
end

function M.body_filter(rsp, ...)
	if not rsp.chunked then
		return M.next_body_filter(rsp, ...)
	end

	for i=1,select("#", ...) do
		local buf = select(i, ...)
		if buf.size > 0 then
			local size = strformat("%X\r\n", buf.size)
			buf:append(eol)
			if buf.eof then
				buf:append(eof)
			end
			local ret,err = M.next_body_filter(rsp, rsp.bufpool:get(size), buf)
			if err then return ret,err end
		else
			if buf.eof then
				buf:append(eof)
			end
			local ret,err = M.next_body_filter(rsp, buf)
			if err then return ret,err end
		end
	end

	return true
end

return M
