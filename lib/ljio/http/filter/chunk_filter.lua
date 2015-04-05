-- Copyright (C) Jinhua Luo

local M = {}

local format = string.format
local tinsert = table.insert

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

function M.body_filter(rsp, buf)
	if rsp.chunked then
		if buf.size > 0 then
			local prefix = format("%X\r\n", buf.size)
			tinsert(buf, 1, prefix)
			tinsert(buf, eol)
			buf.size = buf.size + #prefix + #eol
		end

		if buf.eof then
			tinsert(buf, eof)
			buf.size = buf.size + #eof
		end
	end

	return M.next_body_filter(rsp, buf)
end

return M
