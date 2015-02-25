local chunk = require("http.filter.chunk_filter")
local writer = require("http.filter.writer_filter")

chunk.next_header_filter = writer.header_filter
chunk.next_body_filter = writer.body_filter

return {
	run_next_header_filter = function(rsp)
		return rsp.headers_sent or chunk.header_filter(rsp)
	end,
	run_next_body_filter = function(rsp, ...)
		if rsp.eof then return false, "eof" end
		if not rsp.headers_sent then
			local ret,err = chunk.header_filter(rsp)
			if err then return ret,err end
		end
		return chunk.body_filter(rsp, ...)
	end
}
