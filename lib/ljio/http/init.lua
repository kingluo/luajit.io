-- Copyright (C) Jinhua Luo

local C = require("ljio.cdef")
local ffi = require("ffi")
local tcpd = require("ljio.socket.tcpd")
local pcre = require("ljio.core.pcre")
local sha1 = require("ljio.core.sha1")
local shdict = require("ljio.core.shdict")

local filter = require("ljio.http.filter")
local run_next_header_filter = filter.run_next_header_filter
local run_next_body_filter = filter.run_next_body_filter

local copy_values = require("ljio.http.buf").copy_values

local http_time = require("ljio.core.utils").http_time
local constants = require("ljio.http.constants")
local special_rsp = constants.special_rsp
local status_tbl = constants.status_tbl

local byte = string.byte
local char = string.char
local strsub = string.sub
local strfind = string.find
local match = string.match
local gsub = string.gsub
local lower = string.lower
local gmatch = string.gmatch

local tinsert = table.insert
local tsort = table.sort
local tconcat = table.concat

local percent = byte("%")
local plus = byte("+")
local dot = byte(".")
local question = byte("?")
local slash = byte("/")
local space = byte(" ")
local colon = byte(":")
local eol1 = byte("\r")
local eol2 = byte("\n")

local g_http_cfg
local http_req_mt = {__index = {}}
local http_rsp_mt = {__index = {}}
local sid_pool = 1
local v_time_t = ffi.new("time_t[1]")
local if_modified_tm = ffi.new("struct tm")
local fstat = ffi.new("struct stat[1]")

local function escape(s)
    s = gsub(s, "([^%w%.%- ])", function(c)
        return format("%%%02X", byte(c))
    end)
    return gsub(s, " ", "+")
end

local function unescape(s)
    s = gsub(s,"+"," ")
    return (gsub(s, "%%(%x%x)", function(hex)
        return char(tonumber(hex, 16))
    end))
end

local function decode_args(query)
    local uri_args = {}

    for n, v in gmatch(query, "([^=&]+)=?([^=&]*)&?") do
        n = unescape(n)
        v = v == "" and true or unescape(v)

        if not uri_args[n] then
            uri_args[n] = v
        else
            if type(uri_args[n]) ~= "table" then
                uri_args[n] = {uri_args[n]}
            end
            tinsert(uri_args[n], v)
        end
    end

    return uri_args
end

local g_path_tmp

local function parse_url(url, len)
    if url[0] ~= slash then
        return nil
    end

    if len == 1 then
        return "/"
    end

    if len > g_http_cfg.large_client_header_buffers[2] then
        return nil
    end

    if g_path_tmp == nil then
        g_path_tmp = ffi.new("char[?]", g_http_cfg.large_client_header_buffers[2], "/")
    end

    local path = g_path_tmp

    local pos1 = 0
    local pos2 = 0
    local qpos
    local need_unescape = false

    for i = 1, len do
        local c
        if i < len then
            c = url[i]
        end
        if c == slash or c == question or c == nil then
            local n = pos2 - pos1
            if n == 2 and C.memcmp(path + pos1 + 1, "..", 2) == 0 then
                if pos1 > 0 then
                    local ptr = ffi.cast("char*", C.memrchr(path, slash, pos1))
                    pos2 = ptr - path
                    pos1 = pos2
                else
                    pos2 = pos1
                end
            elseif n == 1 and path[pos1 + 1] == dot then
                pos2 = pos1
            elseif path[pos2] ~= slash and c ~= nil and c ~= question then
                pos2 = pos2 + 1
                path[pos2] = c
                pos1 = pos2
            end

            if c == question then
                qpos = i
                break
            end
        else
            pos2 = pos2 + 1
            path[pos2] = c
            if not need_unescape and (c == percent or c == plus) then
                need_unescape = true
            end
        end
    end

    path = ffi.string(path, pos2 + 1)
    if need_unescape then
        path = unescape(path)
    end

    local query
    if qpos then
        query = ffi.string(url + qpos + 1, len - qpos)
    end

    return path, query
end

local function parse_header(rbuf, avaliable, ctx)
    for i = 1,avaliable do
        local c = rbuf.cp2[0]

        if ctx.inline == 0 then
            if c == eol1 then
                ctx.inline = 1
            end
        elseif ctx.inline == 1 then
            ctx.inline = c == eol2 and 2 or 0
        end

        if ctx.phase == "header" then
            if ctx.colon_offset == 0 and c == colon then
                ctx.colon_offset = rbuf.cp2 - rbuf.cp1
            end
        end

        if ctx.inline == 2 then
            ctx.inline = 0

            if rbuf.cp1 == rbuf.cp2 - 1 then
                rbuf.cp2 = rbuf.cp2 + 1
                return nil, "done"
            end

            if rbuf.cp2 - rbuf.cp1 + 1 > ctx.quota then
                return nil, 414
            end

            if ctx.phase == "line" then
                local ptr = ffi.cast("char*", C.memchr(rbuf.cp1, space, rbuf.cp2 - rbuf.cp1 - 1))
                if ptr == nil then
                    return nil, 400
                end
                ctx.method = ffi.string(rbuf.cp1, ptr - rbuf.cp1)
                rbuf.cp1 = ptr + 1
                ptr = ffi.cast("char*", C.memchr(rbuf.cp1, space, rbuf.cp2 - rbuf.cp1 - 1))
                if ptr == nil then
                    return nil, 400
                end
                local path, query = parse_url(rbuf.cp1, ptr - rbuf.cp1)
                if path == nil then
                    return nil, 400
                end
                ctx.url = {path = path, query = query}
                ctx.version = ffi.string(ptr + 6, rbuf.cp2 - ptr - 5)
                rbuf.cp1 = rbuf.cp2 + 1
                ctx.phase = "header"
            elseif ctx.phase == "header" then
                if ctx.colon_offset == 0 then
                    return nil, 400
                end
                local ptr = rbuf.cp1 + ctx.colon_offset
                local name = ffi.string(rbuf.cp1, ptr - rbuf.cp1)
                local value = ffi.string(ptr + 2, rbuf.cp2 - ptr - 3)
                if ctx.headers == nil then
                    ctx.headers = {}
                end
                ctx.colon_offset = 0
                ctx.headers[lower(name)] = value
                rbuf.cp1 = rbuf.cp2 + 1
            end
        end

        rbuf.cp2 = rbuf.cp2 + 1
    end
end

local function read_header(sock, ctx)
    local headers, method, url, version
    -- sock:settimeout((g_http_cfg.client_header_timeout or 60) * 1000)

    local quota = g_http_cfg.large_client_header_buffers[2]
    sock.read_quota = sock.stats.consume + g_http_cfg.large_client_header_buffers[1] * quota
    ctx.phase = "line"
    ctx.inline = 0
    ctx.colon_offset = 0
    ctx.quota = quota
    local ret, err = sock:receive(parse_header, ctx)
    sock.read_quota = nil

    if err and err ~= "done" then
        if err == "closed" and not sock.closed then
            err = 400
        elseif err == "timeout" then
            err = 408
        end
        return err
    end
end

function http_req_mt.__index.read_chunk(self)
    if self.headers["transfer-encoding"] ~= "chunked" then
        return nil, "not chunked"
    end

    local sock = self.sock
    local read_quota = sock.read_quota
    sock.read_quota = nil

    local line, err = sock:receive()
    if err then
        sock.read_quota = read_quota
        return nil, err
    end

    local size = tonumber(gsub(line, ";.*", ""), 16)
    if not size then
        sock.read_quota = read_quota
        return nil, "invalid chunk size"
    end

    if size > 0 then
        local chunk, err = sock:receive(size)
        if chunk then
            sock:receive()
        else
            sock.read_quota = read_quota
            return nil, err
        end
        sock.read_quota = read_quota
        return chunk
    end

    read_header(sock)
    sock.read_quota = read_quota
end

function http_req_mt.__index.discard_body(self)
    if self.headers["transfer-encoding"] == "chunked" then
        repeat
            local chunk = self:read_chunk()
        until chunk == nil
        return
    end

    assert(self.sock.read_quota)
    if self.sock.stats.consume < self.sock.read_quota then

    local sock = self.sock
    local rbuf = sock.rbuf
    if sock.read_quota <= sock.stats.rbytes then
        rbuf.cp1 = rbuf.rp
        rbuf.cp2 = rbuf.rp
        sock.stats.consume = sock.read_quota
        return
    end

    local pending = sock.read_quota - sock.stats.rbytes
    local read_hook = sock.hook.read
    local rbytes = 0
    sock.hook.read = function(self, rbuf, size)
        local len, err = read_hook(self, rbuf, size)
        if len > 0 then
            rbytes = rbytes + len
            if rbytes >= pending then
                local left = rbytes - pending
                rbuf.rp = rbuf.rp + left
                return left, "discard_body done"
            end
        end
        return 0,err
    end

    assert(sock:receive("*a") == "")
    sock.hook.read = read_hook
end
end

function http_req_mt.__index.get_uri_args(self)
    if not self.uri_args then
        self.uri_args = decode_args(self.url.query)
    end
    return self.uri_args
end

function http_req_mt.__index.get_post_args(self)
    if self.post_args then
        return self.post_args
    end

    local typ = self.headers["content-type"]
    local te = self.headers["transfer-encoding"]
    if self.method ~= "POST"
        or typ ~= "application/x-www-form-urlencoded"
        or (te and te ~= "identity") then
        return nil, "not available"
    end

    local body = self.sock:receive("*a")
    self.post_args = decode_args(body)
    return self.post_args
end

local function http_req_new(sock)
    return setmetatable({sock = sock}, http_req_mt)
end

function http_rsp_mt.__index.get_sid(self)
    if self.sid then return self.sid end
    local cookie = self.req.headers["cookie"]
    local sid
    if cookie then
        sid = match(cookie, "SESSIONID=([^;%s]+)")
    else
        sid = tostring(os.time()) .. sid_pool
        sid_pool = sid_pool + 1
        self.headers['Set-Cookie'] = 'SESSIONID=' .. sid .. '; path=/ ; HttpOnly'
    end
    self.sid = sid
    return sid
end

function http_rsp_mt.__index.send_headers(self)
    return run_next_header_filter(self)
end

function http_rsp_mt.__index.print(self, ...)
    local str = copy_values(nil, ...)
    return run_next_body_filter(self, str)
end

function http_rsp_mt.__index.say(self, ...)
    local str = copy_values("\n", ...)
    return run_next_body_filter(self, str)
end

function http_rsp_mt.__index.sendfile(self, path, offset, size, eof, absolute)
    if not absolute then
        local lcf = self.req.lcf or self.req.srvcf
        path = (lcf.root or ".") .. "/" .. path
    end

    if size == nil then
        local f = io.open(path)
        if f == nil then
            return 0
        end
        size = f:seek('end')
        f:close()
    end

    if size == 0 then
        return 0
    end

    if not eof then
        return run_next_body_filter(self, {path = path, offset = offset or 0, size = size})
    end

    run_next_body_filter(self, {path = path, offset = offset or 0, size = size})
    return run_next_body_filter(self, constants.eof)
end

function http_rsp_mt.__index.flush(self)
    return run_next_body_filter(self, constants.flush)
end

function http_rsp_mt.__index.finalize(self, status)
    if self.finalized then return true end
    self.finalized = true

    self.req:discard_body()

    if status then self.status = status end

    if not self.headers_sent and self.status ~= 200
        and self.status ~= 304 and self.status ~= 204 and self.status > 200 then
        local str = special_rsp[self.status]
        self.headers["content-type"] = "text/html"
        self.headers["content-length"] = #str
        run_next_body_filter(self, str)
    end

    return run_next_body_filter(self, constants.eof)
end

function http_rsp_mt.__index.exit(self, status)
    if status then self.status = status end
    return coroutine.exit(true)
end

local function encode_args(args)
    local t = {}
    for k,v in pairs(args) do
        k = escape(k)
        if type(v) == "table" then
            for _,v2 in ipairs(v) do
                if type(v2) == "string" then
                    v2 = escape(v2)
                end
                tinsert(t, k .. "=" .. v2)
            end
        else
            if type(v) == "string" then
                v = escape(v)
            end
            tinsert(t, k .. "=" .. v)
        end
    end
    return tconcat(t, "&")
end

function http_rsp_mt.__index.encode_args(self, args)
    return encode_args(args)
end

function http_rsp_mt.__index.exec(self, uri, args)
    if self.headers_sent then
        print("exec must be taken before any output happens")
        return false
    end
    self.uri_args = nil
    local path = uri
    if not args then
        local i,j = strfind(uri, "?", 1, true)
        if i then
            path = strsub(uri, 1, i-1)
            args = strsub(uri, 1, i+1)
        end
    else
        self.uri_args = args
        args = self:encode_args(args)
    end
    self.req.url.path = path
    self.req.url.query = args
    self.exec = true
    return coroutine.exit(true)
end

function http_rsp_mt.__index.redirect(self, uri, status)
    if self.headers_sent then
        print("redirect must be taken before any output happens")
        return false
    end

    if strsub(uri,1,1) == "/" then
        local scheme = self.sock.use_ssl and "https://" or "http://"
        local port = (self.sock.srv_port ~= 80) and (":" .. self.sock.srv_port) or ""
        local host = self.req.headers["host"] or (self.sock.srv_ip .. port)
        uri = scheme .. host .. uri
    end

    self.headers["Location"] = uri
    self.status = status or 302
    return coroutine.exit(true)
end

local function if_not_modified(rsp)
    local req = rsp.req
    local lcf = req.lcf or req.srvcf
    local path = req.url.path
    path = (lcf.root or ".") .. '/' .. path
    if C.syscall(C.SYS_stat, ffi.cast("const char*", path), fstat) == 0 then
        local mtime = fstat[0].st_mtime
        rsp.headers["expires"] = http_time(C.time(nil) + 5*60*60)
        rsp.headers["cache-control"] = "public, max-age=" .. 5*60*60
        rsp.headers["last-modified"] = http_time(mtime)
        local str = rsp.req.headers["if-modified-since"]
        if str then
            C.strptime(str, "%a, %d %h %Y %H:%M:%S", if_modified_tm)
            local rmtime = C.mktime(if_modified_tm)
            v_time_t[0] = mtime
            if rmtime >= C.mktime(C.gmtime(v_time_t)) then
                return rsp:finalize(304)
            end
        end
    end
end

local function try_file(self, path)
    local req = self.req
    local lcf = req.lcf or req.srvcf
    local path = path or req.url.path

    local fpath = (lcf.root or ".") .. '/' .. path
    local f = io.open(fpath)
    if f == nil then return self:finalize(404) end
    local flen = f:seek('end')
    f:close()

    local ext = match(path, "%.([^%.]+)$")
    self.headers["content-type"] = lcf.mime_types[ext]
    self.headers["content-length"] = flen

    local sent,err = self:sendfile(fpath, 0, flen, true, true)
    if err then
        return self:finalize(404)
    end
    return sent
end

local hash_mt = {
    __newindex = function(tbl, key, value)
        if value ~= nil and rawget(tbl, key) == nil then
            rawset(tbl, #tbl + 1, key)
        end
        rawset(tbl, key, value)
    end
}

local function http_rsp_new(req, sock)
    return setmetatable({headers_sent = false,
        headers = setmetatable({}, hash_mt),
        sock = sock, req = req, status=200}, http_rsp_mt)
end

--#--

local function more_than(a,b)
    return a > b
end

local function http_parse_conf(cfg)
    g_http_cfg = cfg

    if cfg.client_header_timeout == nil then
        cfg.client_header_timeout = 60
    end

    if cfg.large_client_header_buffers == nil then
        cfg.large_client_header_buffers = {4, 8 * 1024}
    end

    if cfg.gzip_types == nil then
        cfg.gzip_types = {}
    end
    cfg.gzip_types["text/html"] = true
    if cfg.gzip_min_length == nil then
        cfg.gzip_min_length = 20
    end

    cfg.mime_types = {}
    local types = cfg.types
    if strsub(cfg.types,1,1) ~= "/" then
        types = cfg.conf_prefix .. "/" .. cfg.types
    end
    types = io.open(types)
    assert(types)
    local data = types:read("*a")
    types:close()
    assert(data)
    for typ,exts in gmatch(data, "([^;%s]+)%s+([a-zA-Z0-9%s]+);") do
        for ext in gmatch(exts, "%w+") do
            cfg.mime_types[ext] = typ
        end
    end

    local global_mt = {__index=cfg}
    for _,srv in ipairs(cfg) do
        setmetatable(srv, global_mt)
        srv.location_hash = {
            exact_hash={},
            prefix_hash={},
            pattern={}
        }
        local shash = srv.location_hash
        local server_mt = {__index=srv}
        for _,location in ipairs(srv.location) do
            setmetatable(location, server_mt)
            if location[1] == "=" then
                shash.exact_hash[location[2]] = location
            elseif location[1] == "^" or location[1] == "^~" then
                shash.prefix_hash[location[2]] = location
            else
                if location[1] == "~*" then
                    location[2] = lower(location[2])
                end
                tinsert(shash.pattern, location)
            end
        end

        --#--
        local tmp = {}
        for k in pairs(shash.prefix_hash) do
            tmp[#k] = 1
        end
        shash.prefix_size_hash = {}
        for k in pairs(tmp) do
            tinsert(shash.prefix_size_hash, k)
        end
        tsort(shash.prefix_size_hash, more_than)
        shash.prefix_size_hash.n = #shash.prefix_size_hash
    end

    for port,addresses in pairs(cfg.srv_tbl) do
        for address,srv_list in pairs(addresses) do
            srv_list.extra_hash = {}
            srv_list.prefix_hash = {}
            srv_list.postfix_hash = {}
            srv_list.pattern = {}

            for _,srv in ipairs(srv_list) do
                for _,host in ipairs(srv.server_name) do
                    local prefix = strsub(host,1,1)
                    local postfix = strsub(host,#host)
                    if prefix == "~" then
                        tinsert(srv_list.pattern, {host=strsub(host,2),srv=srv})
                    elseif prefix == "*" or prefix == "." then
                        if prefix == "*" then host = strsub(host,2) end
                        srv_list.prefix_hash[host] = srv
                        if prefix == "." then
                            srv_list.extra_hash[host] = srv
                        end
                    elseif postfix == "*" then
                        srv_list.postfix_hash[strsub(host,1,#host-1)] = srv
                    else
                        srv_list.extra_hash[host] = srv
                    end
                end
            end

            --#--
            local tmp = {}
            for k in pairs(srv_list.prefix_hash) do
                tmp[#k] = 1
            end
            srv_list.prefix_size_hash = {}
            for k in pairs(tmp) do
                tinsert(srv_list.prefix_size_hash, k)
            end
            tsort(srv_list.prefix_size_hash, more_than)
            srv_list.prefix_size_hash.n = #srv_list.prefix_size_hash

            --#--
            local tmp = {}
            for k in pairs(srv_list.postfix_hash) do
                tmp[#k] = 1
            end
            srv_list.postfix_size_hash = {}
            for k in pairs(tmp) do
                tinsert(srv_list.postfix_size_hash, k)
            end
            tsort(srv_list.postfix_size_hash, more_than)
            srv_list.postfix_size_hash.n = #srv_list.postfix_size_hash
        end
    end
end

local function match_aux(...)
    local n_capture = select("#", ...)
    local ret = select(1, ...)
    if n_capture > 0 and type(ret) ~= "nil" then
        return {...}
    end
end

local function find_first_less(t, elem)
    if t.n == 0 then
        return
    end

    local m,n = 1,t.n
    local mid
    while m <= n do
        mid = math.floor((m+n)/2)
        if t[mid] >= elem then
            m = mid + 1
        elseif t[mid] < elem then
            n = mid - 1
            if n > 0 and t[n] >= elem then
                break
            end
        end
    end

    if t[mid] < elem then
        return mid
    end
end

local function find_first_less_equal(t, elem)
    if t.n == 0 then
        return
    end

    local m,n = 1,t.n
    local mid
    while m <= n do
        mid = math.floor((m+n)/2)
        if t[mid] > elem then
            m = mid + 1
        elseif t[mid] <= elem then
            n = mid - 1
            if n > 0 and t[n] > elem then
                break
            end
        end
    end

    if t[mid] <= elem then
        return mid
    end
end

-- ngx api wrappers

local tcp = require("ljio.socket.tcp")
local udp = require("ljio.socket.udp")
local logging = require("ljio.core.logging")

local function get_socket()
    return ngx._req.sock
end

local function get_headers()
    return ngx._req.headers
end

local function get_method()
    return ngx._req.method
end

local function ngx_tcp()
    return tcp.new()
end

local function ngx_log(...)
    return logging.log(...)
end

local function ngx_print(...)
    return ngx._rsp:print(...)
end

local function ngx_say(...)
    return ngx._rsp:say(...)
end

local ngx_mt = {
    __index = {
        req = {socket = get_socket, get_headers = get_headers, get_method = get_method},
        socket = {tcp = ngx_tcp, udp = udp},
        encode_args = encode_args,
        log = ngx_log,
        DEBUG = "debug",
        ERR = "err",
        print = ngx_print,
        say = ngx_say,
        config = {ngx_lua_version = 9011, debug = false},
        null = ffi.new("void*"),
        sleep = coroutine.sleep,
        md5 = require"ljio.core.md5",
        re = {
            match = pcre.match,
            find = pcre.find,
            sub = pcre.sub,
            gsub = pcre.gsub,
        },
        sha1_bin = function(str)
            local ctx = sha1:new()
            ctx:update(str)
            return ctx:final()
        end,
    },
    __newindex = function(t, n, v)
        if n == "status" then
            ngx._rsp.status = v
        end
        rawset(t, n, v)
    end,
}

local function is_args()
    return ngx._req.url.query and "?" or ""
end

local ngx
local function setup_api(req, rsp)
    if ngx == nil then
        ngx = setmetatable({var = {is_args = is_args}}, ngx_mt)
    end
    ngx._req = req
    ngx._rsp = rsp
    ngx.header = rsp.headers
    ngx.var.scheme = req.sock.use_ssl and "https" or "http"
    ngx.var.uri = req.url.path
    ngx.var.query_string = req.url.query
    ngx.var.content_type = req.headers["content-type"]
    ngx.shared = shdict.shared
end

--#--

local function handle_http_request(req, rsp)
    local match_srv
    local srv_list = g_http_cfg.srv_tbl[req.sock.srv_port][req.sock.srv_ip]
        or g_http_cfg.srv_tbl[req.sock.srv_port]["*"]

    if #srv_list > 1 then
        local host = req.headers["host"] or ""
        local hlen = #host

        -- exact name
        match_srv = srv_list.extra_hash[host]

        -- longest wildcard name starting with an asterisk, e.g. "*.example.org"
        if not match_srv then
            local start = find_first_less(srv_list.prefix_size_hash, hlen)
            if start then
                for i = start, srv_list.prefix_size_hash.n do
                    local v = srv_list.prefix_size_hash[i]
                    if srv_list.prefix_hash[strsub(host, hlen-v+1)] then
                        match_srv = v.srv
                        break
                    end
                end
            end
        end

        -- longest wildcard name ending with an asterisk, e.g. "mail.*"
        if not match_srv then
            local start = find_first_less(srv_list.postfix_size_hash, hlen)
            if start then
                for i = start, srv_list.postfix_size_hash.n do
                    local v = srv_list.postfix_size_hash[i]
                    if srv_list.postfix_hash[strsub(host, 1, v)] then
                        match_srv = v.srv
                        break
                    end
                end
            end
        end

        -- first matching regular expression (in order of appearance in a configuration file)
        if not match_srv then
            for _,v in ipairs(srv_list.pattern) do
                if strfind(host, v.host) then
                    match_srv = v.srv
                    break
                end
            end
        end

        if not match_srv then
            match_srv = srv_list.default_server
        end
    end

    if not match_srv then
        match_srv = srv_list[1]
    end

    ::location_matching::

    local location
    if match_srv then
        local shash = match_srv.location_hash
        local path = req.url.path
        local pathlen = #path
        local match_done = false

        -- exact match
        location = shash.exact_hash[path]
        if location then match_done = true end

        -- prefix match
        if not match_done then
            local start = find_first_less_equal(shash.prefix_size_hash, pathlen)
            if start then
                for i = start, shash.prefix_size_hash.n do
                    local v = shash.prefix_size_hash[i]
                    local slcf = shash.prefix_hash[strsub(path, 1, v)]
                    if slcf then
                        location = slcf
                        match_done = (slcf[1] == "^~")
                        break
                    end
                end
            end
        end

        -- pattern match
        if not match_done then
            for _,slcf in ipairs(shash.pattern) do
                local modifier,pat = slcf[1],slcf[2]
                if modifier == "~" then
                    req.match_data = match_aux(match(path, pat))
                elseif modifier == "~*" then
                    req.match_data = match_aux(match(lower(path), pat))
                elseif modifier == "f"  then
                    local checker = coroutine.create(pat)
                    coroutine.resume(checker, req)
                    req.match_data = match_aux(select(2, coroutine.wait(checker)))
                end
                if req.match_data then
                    location = slcf
                    break
                end
            end
        end
    end

    req.srvcf = match_srv
    req.lcf = location

    if location then
        local lcf = req.lcf or req.srvcf
        if lcf.package_path then
            package.path = lcf.package_path
        end

        local fn = location[3]
        if type(fn) == 'string' then
            local ret
            ret,fn = pcall(require, fn)
            if ret == false then
                return rsp:finalize(500)
            end
        end

        setup_api(req, rsp)

        local handler = coroutine.create(fn, nil)
        coroutine.resume(handler, req, rsp)
        local ret, err = coroutine.wait(handler)
        if ret == false and err ~= "exit_group" and err ~= "exit" then
            return rsp:finalize(500)
        end

        coroutine.wait_descendants()

        if rsp.exec == true then
            rsp.exec = false
            goto location_matching
        end

        return rsp:finalize()
    end

    return if_not_modified(rsp) or try_file(rsp)
end

local function finalize_conn(sock, status, body)
    local body = body or special_rsp[status]
    sock:send(status_tbl[status],
        "server: luajit.io\r\ncontent-type: text/html\r\n",
        "content-length: " .. #body .. "\r\n",
        "date: " .. http_time() .. "\r\nconnection: close\r\n\r\n",
        body)
end

local function http_handler(sock)
    local req = http_req_new(sock)
    local err = read_header(sock, req)

    if err then
        if err ~= "closed" then
            finalize_conn(sock, err)
        end
        return
    end

    local rsp = http_rsp_new(req, sock)

    sock.read_quota = sock.stats.consume + (req.headers["content-length"] or 0)
    handle_http_request(req, rsp)
    sock.read_quota = nil
    return http_handler(sock)
end

local function run(cfg)
    return tcpd(cfg, http_parse_conf, http_handler)
end

return run
