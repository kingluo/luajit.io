local gzip = require("http.filter.gzip_filter")
local chunk = require("http.filter.chunk_filter")
local writer = require("http.filter.writer_filter")

gzip.next_header_filter = chunk.header_filter
gzip.next_body_filter = chunk.body_filter
chunk.next_header_filter = writer.header_filter
chunk.next_body_filter = writer.body_filter

return {
	run_next_header_filter = function(rsp)
		return rsp.headers_sent or gzip.header_filter(rsp)
	end,
	run_next_body_filter = function(rsp, ...)
		if rsp.eof then return false, "eof" end
		if not rsp.headers_sent then
			local ret,err = gzip.header_filter(rsp)
			if err then return ret,err end
		end
		return gzip.body_filter(rsp, ...)
	end
}
