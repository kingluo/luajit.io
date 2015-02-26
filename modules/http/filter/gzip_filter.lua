local M = {}

local C = require("cdef")
local ffi = require("ffi")
local zlib = ffi.load("z")

local tinsert = table.insert
local tconcat = table.concat

local ZLIB_VERSION = "1.2.8"
local CHUNK = 16384
local buf_in = ffi.new("char[?]", CHUNK)
local buf_out = ffi.new("char[?]", CHUNK)

function M.header_filter(rsp)
	local srvcf = rsp.req.srvcf
	local lcf = rsp.req.lcf or srvcf
	local len = rsp.headers["content-length"]
	local typ = rsp.headers["content-type"]
	if typ then
		typ = string.match(typ, "[^;]+")
	end
	if lcf.gzip and rsp.status == 200
		and (lcf.gzip_min_length == nil or (len == nil or len >= lcf.gzip_min_length))
		and (lcf.gzip_types == nil or (typ == nil or lcf.gzip_types[typ]
			or srvcf.gzip_types[typ])) then
		rsp.headers["content-encoding"] = "gzip"
		rsp.headers["content-length"] = nil
		rsp.gzip = {}
	end
	return M.next_header_filter(rsp)
end

local function copy_buf(buf, size)
	size = size or 0
	for _,v in ipairs(buf) do
		local typ = type(v)
		if typ == "table" then
			size = copy_buf(buf, size)
		else
			ffi.copy(buf_in + size, v, #v)
			size = size + #v
		end
	end
	return size
end

local function compress_chunk(strm, size, flush)
	local t = {}
	local ret
	strm.avail_in = size
	strm.next_in = buf_in
	repeat
		strm.avail_out = CHUNK
		strm.next_out = buf_out
		ret = zlib.deflate(strm, flush)
		assert(ret ~= C.Z_STREAM_ERROR)
		local have = CHUNK - strm.avail_out
		tinsert(t, ffi.string(buf_out, have))
	until (strm.avail_out ~= 0)
	assert(strm.avail_in == 0)
	return ret,tconcat(t)
end

function M.body_filter(rsp, ...)
	if not rsp.gzip then
		return M.next_body_filter(rsp, ...)
	end

	local gzip = rsp.gzip
	if not gzip.strm then
		gzip.strm = ffi.new("z_stream")
		assert(zlib.deflateInit2_(gzip.strm, rsp.req.lcf.gzip_comp_level or 1,
			C.Z_DEFLATED, 31, 8, 0,
			ZLIB_VERSION, ffi.sizeof(gzip.strm)) == C.Z_OK)
	end

	for i=1,select("#", ...) do
		local buf = select(i, ...)

		local flush = C.Z_NO_FLUSH
		if buf.eof then
			flush = C.Z_FINISH
		elseif buf.flush then
			flush = C.Z_SYNC_FLUSH
		end

		if buf.is_file then
			assert(buf.size > 0)
			local fd = C.open(buf.path, 0)
			assert(fd > 0)
			if buf.offset > 0 then
				assert(C.lseek(fd, buf.offset, C.SEEK_SET) == buf.offset)
			end
			local size = buf.size
			while true do
				local chunksz = (size > CHUNK) and CHUNK or size
				local sz = C.read(fd, buf_in, chunksz)
				size = size - sz
				local ret,str = compress_chunk(gzip.strm, sz, flush)
				if ret == C.Z_STREAM_END then
					assert(buf.eof)
					zlib.deflateEnd(gzip.strm)
				end
				local flush, eof
				if sz < chunksz or size == 0 then
					flush = buf.flush
					eof = buf.eof
				end
				local ret,err = M.next_body_filter(rsp, {size=#str, str, flush=flush, eof=eof})
				if err then return ret,err end
				if sz < chunksz or size == 0 then break end
			end
			assert(C.close(fd) == 0)
		else
			assert(buf.size < CHUNK)
			assert(copy_buf(buf) == buf.size)
			local ret,str = compress_chunk(gzip.strm, buf.size, flush)
			local ret,err = M.next_body_filter(rsp, {size=#str, str, eof = buf.eof, flush=buf.flush})
			if err then return ret,err end
		end
	end

	return true
end

return M
