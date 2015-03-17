-- Copyright (C) Jinhua Luo

local C = require("ljio.cdef")
local ffi = require("ffi")
local tcp = require("ljio.socket.tcp")
local URI = require("uri")
local uri_encode = require("uri._util").uri_encode
local uri_decode = require("uri._util").uri_decode

local filter = require("ljio.http.filter")
local run_next_header_filter = filter.run_next_header_filter
local run_next_body_filter = filter.run_next_body_filter

local create_bufpool = require("ljio.http.buf")
local http_time = require("ljio.core.utils").http_time

local strsub = string.sub
local strfind = string.find
local strmatch = string.match
local strgsub = string.gsub
local strformat = string.format
local strlower = string.lower

local tinsert = table.insert
local tsort = table.sort
local tconcat = table.concat

local function unescape(s)
	s = strgsub(s,"+"," ")
	return uri_decode(s)
end

local function decode_args(query)
	local uri_args = {}
	local i = 0
	local j = 0
	local match
	while true do
		i,j,match = strfind(query, "([^&]+)", j+1)
		if not match then break end
		local n = match
		local v
		local i = strfind(match,"=",1,true)
		if i then
			n = strsub(match,1,i-1)
			v = strsub(match,i+1)
		end

		n = unescape(n)
		if v then v = unescape(v) end
		v = v or true

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

local function receive_headers(sock, headers)
	local line, name, value, err
	headers = headers or {}

	-- get first line
	line, err = sock:receive()
	if err then return nil, err end

	-- headers go until a blank line is found
	while line ~= "" do
		-- get field-name and value
		name, value = strmatch(line, "^(.-):%s*(.*)")
		if not (name and value) then return nil, "malformed reponse headers" end
		name = string.lower(name)

		-- get next line (value might be folded)
		line, err = sock:receive()
		if err then return nil, err end

		-- unfold any folded values
		while strfind(line, "^%s") do
			value = value .. line
			line = sock:receive()
			if err then return nil, err end
		end

		-- save pair in table
		if headers[name] then headers[name] = headers[name] .. ", " .. value
		else headers[name] = value end
	end

	return headers
end

local http_req_mt = {__index={}}

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

	local size = tonumber(strgsub(line, ";.*", ""), 16)
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

	receive_headers(sock, self.headers)
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
	if self.sock.stats.consume == self.sock.read_quota then
		return
	end

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

function http_req_mt.__index.get_uri_args(self)
	if not self.uri_args then
		self.uri_args = decode_args(self.url:query())
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

local function http_req_new(method, url, headers, sock)
	return setmetatable({method = method, url = url,
		headers = headers, sock = sock}, http_req_mt)
end

local http_rsp_mt = {__index = {bufpool = create_bufpool(100)}}

local sid_pool = 1
function http_rsp_mt.__index.get_sid(self)
	if self.sid then return self.sid end
    local cookie = self.req.headers["cookie"]
	local sid
	if cookie then
		sid = string.match(cookie, "SESSIONID=([^;%s]+)")
	else
		sid = tostring(os.time()) .. sid_pool
		sid_pool = sid_pool + 1
		self.headers['Set-Cookie'] = 'SESSIONID=' .. sid .. '; path=/'
	end
	self.sid = sid
    return sid
end

function http_rsp_mt.__index.send_headers(self)
	return run_next_header_filter(self)
end

function http_rsp_mt.__index.print(self, ...)
	local buf = self.bufpool:get(...)
	return run_next_body_filter(self, buf)
end

function http_rsp_mt.__index.say(self, ...)
	local buf = self.bufpool:get(...)
	buf:append("\n")
	return run_next_body_filter(self, buf)
end

function http_rsp_mt.__index.sendfile(self, path, offset, size, eof)
	local buf = self.bufpool:get()
	buf.is_file = true
	buf.path = path
	buf.offset = offset
	buf.size = size
	buf.eof = eof
	return run_next_body_filter(self, buf)
end

function http_rsp_mt.__index.flush(self)
	local buf = self.bufpool:get()
	buf.flush = true
	return run_next_body_filter(self, buf)
end

local special_rsp_template = [[
<html>
<head><title>$status</title></head>
<body bgcolor="white">
<center><h1>$status</h1></center>
<hr><center>luajit.io</center>
</body>
</html>
]]

local function content_aux(status)
	return string.gsub(special_rsp_template, "%$(%w+)", {status=status})
end

local special_rsp = {
	[302] = content_aux("302 Found");
	[400] = content_aux("400 Bad Request");
	[403] = content_aux("403 Forbidden");
	[404] = content_aux("404 Not Found");
	[500] = content_aux("500 Internal Server Error");
	[501] = content_aux("501 Not Implemented");
	[503] = content_aux("503 Service Unavailable");
}

function http_rsp_mt.__index.finalize(self, status)
	if self.finalized then return true end
	self.finalized = true

	self.req:discard_body()

	if status then self.status = status end
	local buf = self.bufpool:get()
	buf.eof = true
	if not self.headers_sent and self.status ~= 200
		and self.status ~= 304 and self.status ~= 204 and self.status > 200 then
		local str = special_rsp[self.status]
		self.headers["content-type"] = "text/html"
		self.headers["content-length"] = #str
		buf:append(str)
	end
	return run_next_body_filter(self, buf)
end

function http_rsp_mt.__index.exit(self, status)
	if status then self.status = status end
	return coroutine.exit(true)
end

function http_rsp_mt.__index.encode_args(self, args)
	local t = {}
	for k,v in pairs(args) do
		k = uri_encode(k)
		if type(v) == "table" then
			for _,v2 in ipairs(v) do
				if type(v2) == "string" then
					v2 = uri_encode(v2)
				end
				tinsert(t, k .. "=" .. v2)
			end
		else
			if type(v) == "string" then
				v = uri_encode(v)
			end
			tinsert(t, k .. "=" .. v)
		end
	end
	return tconcat(t, "&")
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
	self.req.url:path(path)
	self.req.url:query(args)
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

local v_time_t = ffi.new("time_t[1]")
local if_modified_tm = ffi.new("struct tm")
local fstat = ffi.new("struct stat[1]")

local function check_if_modified(rsp)
	local req = rsp.req
	local lcf = req.lcf or req.srvcf
	local path = req.url:path()
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

function http_rsp_mt.__index.try_file(self, path, eof, absolute)
	if eof == nil then eof = true end
	local req = self.req
	local lcf = req.lcf or req.srvcf
	local path = path or req.url:path()
	local ext = string.match(path, "%.([^%.]+)$")
	if self.headers["content-type"] == nil then
		self.headers["content-type"] = lcf:get_mime_types()[ext] or "application/octet-stream"
	end
	local fpath
	if absolute then
		fpath = path
	else
		fpath = (lcf.root or ".") .. '/' .. path
	end
	local f = io.open(fpath)
	if f == nil then return self:finalize(404) end
	local flen = f:seek('end')
	f:close()
	self.headers["content-length"] = flen

	local sent,err = self:sendfile(fpath, 0, flen, eof)
	if err then
		return self:finalize(404)
	end
	return sent
end

local function http_rsp_new(req, sock)
	return setmetatable({headers_sent = false, headers = {},
		sock = sock, req = req, status=200}, http_rsp_mt)
end

--#--

local g_http_cfg

local function get_mime_types(cf)
	if cf.mime_types then
		return cf.mime_types
	else
		cf.mime_types = {}
	end
	local path = cf.types
	if strsub(cf.types,1,1) ~= "/" then
		path = cf.conf_path .. "/" .. cf.types
	end
	local f = io.open(path)
	assert(f)
	local data = f:read("*a")
	assert(data)
	for typ,exts in string.gmatch(data, "([^;%s]+)%s+([a-zA-Z0-9%s]+);") do
		for ext in string.gmatch(exts, "%w+") do
			cf.mime_types[ext] = typ
		end
	end
	f:close()
	return cf.mime_types
end

local function more_than(a,b)
	return a > b
end

local function http_parse_conf(cfg)
	g_http_cfg = cfg

	cfg.get_mime_types = get_mime_types

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
					location[2] = strlower(location[2])
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
		local path = req.url:path()
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
					req.match_data = match_aux(strmatch(path, pat))
				elseif modifier == "~*" then
					req.match_data = match_aux(strmatch(strlower(path), pat))
				elseif modifier == "f"  then
					local checker = coroutine.spawn(pat, nil, req)
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
			print(fn)
				return rsp:finalize(500)
			end
		end

		local handler = coroutine.spawn(fn, nil, req, rsp)
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

	if check_if_modified(rsp) then return end
	return rsp:try_file()
end

local nodelay = ffi.new("int[1]", 1)
local function http_handler(sock)
	assert(C.setsockopt(sock.fd, C.IPPROTO_TCP, C.TCP_NODELAY, ffi.cast("void*", nodelay), ffi.sizeof("int")) == 0)
	while true do
		local line,err = sock:receive()
		if err then print(err); break end
		local method,url,ver = line:match("(.*) (.*) HTTP/(%d%.%d)")
		local uri = URI:new(url)
		if uri._path == "" then
			uri._path = "/"
		else
			uri._path = unescape(uri._path)
		end
		local headers = receive_headers(sock)
		local req = http_req_new(method, uri, headers, sock)
		local rsp = http_rsp_new(req, sock)

		sock.read_quota = sock.stats.consume + (headers["content-length"] or 0)
		handle_http_request(req, rsp)
		sock.read_quota = nil

		if headers["connection"] == "close" then
			sock:close()
			break
		end
	end
end

local function run(cfg)
	return tcp(cfg, http_parse_conf, http_handler)
end

return run
