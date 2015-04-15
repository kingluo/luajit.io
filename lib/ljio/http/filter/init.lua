-- Copyright (C) Jinhua Luo

local gzip = require("ljio.http.filter.gzip_filter")

local first_header_filter = gzip.header_filter
local first_body_filter = gzip.body_filter

gzip.next_header_filter = require("ljio.http.filter.write_filter").write_header_filter
gzip.next_body_filter = require("ljio.http.filter.write_filter").write_body_filter

return {
    run_next_header_filter = function(rsp)
        return rsp.headers_sent or first_header_filter(rsp)
    end,
    run_next_body_filter = function(rsp, data)
        if rsp.eof then return false, "eof" end
        if not rsp.headers_sent then
            local ret,err = first_header_filter(rsp)
            if err then return ret,err end
        end
        return (first_body_filter(rsp, data))
    end
}
