-- Copyright (C) Jinhua Luo

local constants = require("ljio.http.constants")

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
	return (M.next_header_filter(rsp))
end

function M.body_filter(rsp, data)
	if rsp.chunked then
		local typ = type(data)
		if typ ~= "cdata" then
			local prefix = format("%X\r\n", typ == "string" and #data or data.size)
			M.next_body_filter(rsp, prefix)
			M.next_body_filter(rsp, data)
			return (M.next_body_filter(rsp, eol))
		elseif data == constants.eof then
			M.next_body_filter(rsp, eof)
		end
	end

	return (M.next_body_filter(rsp, data))
end

return M
