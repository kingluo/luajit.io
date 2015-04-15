-- Copyright (C) Jinhua Luo

local constants = require("ljio.http.constants")

local M = {}

local C = require("ljio.cdef")
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
    if lcf.gzip and (rsp.status == 200 or rsp.status == 403 or rsp.status == 404)
        and (len == nil or len >= lcf.gzip_min_length)
        and (typ ~= nil and (lcf.gzip_types[typ] or srvcf.gzip_types[typ])) then
        rsp.headers["content-encoding"] = "gzip"
        rsp.headers["content-length"] = nil
        rsp.gzip = {}
    end
    return M.next_header_filter(rsp)
end

local function compress_chunk(strm, flush)
    local t = {}
    local ret
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

function M.body_filter(rsp, data)
    local gzip = rsp.gzip

    if not gzip then
        return M.next_body_filter(rsp, data)
    end

    if not gzip.strm then
        gzip.strm = ffi.new("z_stream")
        local lcf = rsp.req.lcf or rsp.req.srvcf
        local level = lcf.gzip_comp_level or 1
        assert(zlib.deflateInit2_(gzip.strm, level,
            C.Z_DEFLATED, 31, 8, 0,
            ZLIB_VERSION, ffi.sizeof(gzip.strm)) == C.Z_OK)
    end

    local typ = type(data)
    if typ == "table" then
        assert(data.size > 0)
        local fd = C.open(data.path, 0)
        assert(fd > 0)
        if data.offset > 0 then
            assert(C.lseek(fd, data.offset, C.SEEK_SET) == data.offset)
        end
        local size = data.size
        while true do
            local chunksz = (size > CHUNK) and CHUNK or size
            local sz = C.read(fd, buf_in, chunksz)
            size = size - sz
            gzip.strm.avail_in = sz
            gzip.strm.next_in = buf_in
            local ret,str = compress_chunk(gzip.strm, (size == 0) and C.Z_SYNC_FLUSH or C.Z_NO_FLUSH)
            if ret == C.Z_STREAM_END then
                zlib.deflateEnd(gzip.strm)
            end
            local ret,err = M.next_body_filter(rsp, str)
            if err then return ret,err end
            if sz < chunksz or size == 0 then break end
        end
        assert(C.close(fd) == 0)
    else
        if typ == "string" then
            gzip.strm.avail_in = #data
            gzip.strm.next_in = ffi.cast("char*", data)
        else
            gzip.strm.avail_in = 0
        end

        local flush = C.Z_NO_FLUSH
        if data == constants.eof then
            flush = C.Z_FINISH
        elseif data == constants.flush then
            flush = C.Z_SYNC_FLUSH
        end

        local ret,str = compress_chunk(gzip.strm, flush)
        if ret == C.Z_STREAM_END then
            zlib.deflateEnd(gzip.strm)
        end

        local ret,err = M.next_body_filter(rsp, str)
        if err then return ret,err end

        if typ ~= "string" then
            local ret,err = M.next_body_filter(rsp, data)
            if err then return ret,err end
        end
    end

    return true
end

return M
