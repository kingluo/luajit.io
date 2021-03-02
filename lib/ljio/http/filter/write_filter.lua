-- Copyright (C) Jinhua Luo

local http_time = require("ljio.core.utils").http_time
local constants = require("ljio.http.constants")

local format = string.format
local tinsert = table.insert

local postpone_output = 1460

local server = "server: luajit.io\r\n"
local s_server = #server
local ct = "content-type: "
local s_ct = #ct
local eol = "\r\n"
local s_eol = #eol
local eof = "0\r\n\r\n"
local s_eof = #eof
local date = "date: "
local s_date = #date
local conn_close = "connection: close\r\n"
local s_conn_close = #conn_close
local conn_keepalive = "connection: keep-alive\r\n"
local s_conn_keepalive = #conn_keepalive
local colon = ": "
local s_colon = #colon
local chunked = "transfer-encoding: chunked\r\n"
local s_chunked = #chunked

local function write_header_filter(rsp)
    local req = rsp.req

    local status = constants.status_tbl[rsp.status]
    local buf = {size = 0; status, server, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil}
    buf.size = buf.size + #status + s_server

    status = rsp.status
    if rsp.headers["content-length"] == nil
        and status ~= 304 and status ~= 204 and status >= 200 and req.method ~= "HEAD" then
        tinsert(buf, chunked)
        buf.size = buf.size + s_chunked
        rsp.chunked = true
    end

    if rsp.status ~= 304 and rsp.headers["content-type"] == nil then
        local lcf = req.lcf or req.srvcf
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

    if req.headers["connection"] == "close" then
        tinsert(buf, conn_close)
        buf.size = buf.size + s_conn_close
    else
        tinsert(buf, conn_keepalive)
        buf.size = buf.size + s_conn_keepalive
    end

    for _, field in ipairs(rsp.headers) do
        local val = rsp.headers[field]
        if val ~= nil and type(val) ~= "string" then
            val = tostring(val)
        end
        if val then
            tinsert(buf, field)
            tinsert(buf, colon)
            tinsert(buf, val)
            tinsert(buf, eol)
            buf.size = buf.size + #field + s_colon + #val + s_eol
        end
    end

    tinsert(buf, eol)
    buf.size = buf.size + s_eol

    rsp.buf = buf

    rsp.headers_sent = true
end

local function flush_body(rsp)
    if rsp.buf.size > 0 then
        local ret,err = rsp.sock:send(rsp.buf)
        rsp.buf = rsp.eof and nil or {size = 0; nil, nil, nil}
        rsp.body_sent = true
        if err then return nil,err end
    end
    return true
end

local function write_body_filter(rsp, data)
    local typ = type(data)
    if typ == "string" then
        if #data > 0 then
            rsp.buf.size = rsp.buf.size + #data
            if rsp.chunked then
                local prefix = format("%X\r\n", #data)
                tinsert(rsp.buf, prefix)
                tinsert(rsp.buf, data)
                tinsert(rsp.buf, eol)
                rsp.buf.size = rsp.buf.size + #prefix + #data + s_eol
            else
                tinsert(rsp.buf, data)
                rsp.buf.size = rsp.buf.size + #data
            end

            if rsp.buf.size >= postpone_output then
                local ret,err = flush_body(rsp)
                if err then return ret,err end
            end
        end
    elseif typ == "table" then
        if rsp.chunked then
            local prefix = format("%X\r\n", data.size)
            tinsert(rsp.buf, prefix)
        end
        local ret,err = flush_body(rsp)
        if err then return ret,err end
        local ret,err = rsp.sock:sendfile(data.path, data.offset, data.size)
        if err then return ret,err end
        if rsp.chunked then
            tinsert(rsp.buf, eol)
            rsp.buf.size = rsp.buf.size + #eol
        end

        local ret,err = flush_body(rsp)
        if err then return ret,err end
    elseif data == constants.flush or data == constants.eof then
        if data == constants.eof then
            if rsp.chunked then
                tinsert(rsp.buf, eof)
                rsp.buf.size = rsp.buf.size + #eof
            end
            rsp.eof = true
        end

        local ret,err = flush_body(rsp)
        if err then return ret,err end
    end
end

return {
    write_header_filter = write_header_filter,
    write_body_filter = write_body_filter,
}
