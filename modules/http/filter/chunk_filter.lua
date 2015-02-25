local M = {}

local tinsert = table.insert
local strformat = string.format

local eof = "0\r\n\r\n"
local eol = "\r\n"

function M.header_filter(rsp)
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
		if buf.eof then
			buf.size = buf.size + #eof
			tinsert(buf, eof)
			return M.next_body_filter(rsp, buf)
		else
			local size = strformat("%X\r\n", buf.size)
			buf.size = buf.size + #eol
			tinsert(buf, eol)
			local ret,err = M.next_body_filter(rsp, {size=#size, size}, buf)
			if err then return ret,err end
		end
	end

	return true
end

return M
