local C = require("cdef")
local ffi = require("ffi")
local tcp = require("socket.tcp")
local URI = require("uri")
local uri_encode = require("uri._util").uri_encode
local uri_decode = require("uri._util").uri_decode

local filter = require("http.filter")
local run_next_header_filter = filter.run_next_header_filter
local run_next_body_filter = filter.run_next_body_filter

local strsub = string.sub
local strfind = string.find
local strmatch = string.match
local strgsub = string.gsub
local strformat = string.format

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

local function receive_body(sock, headers, chunk_handler)
	local length = tonumber(headers["content-length"])
	if not length or length < 0 then return false, 'invalid content-length' end
	local t = headers["transfer-encoding"]
	if t and t ~= "identity" then
		while true do
			local line, err = sock:receive()
			if err then return false, err end
			-- get chunk size, skip extention
			local size = tonumber(strgsub(line, ";.*", ""), 16)
			if not size then return false, "invalid chunk size" end
			-- was it the last chunk?
			if size > 0 then
				-- if not, get chunk and skip terminating CRLF
				local chunk, err = sock:receive(size)
				if chunk then sock:receive() else return false, err end
				chunk_handler(chunk)
			else
				-- if it was, read trailers into headers table
				receive_headers(sock, headers)
				break
			end
		end
	elseif length then
		local len
		while true do
			if length > 4096 then
				len = 4096
			elseif length == 0 then
				break
			else
				assert(length > 0)
				len = length
			end
			length = length - len
			local chunk, err = sock:receive(len)
			chunk_handler(chunk)
		end
		return true
	end
	return false, 'invalid body'
end

local http_req_mt = {__index={}}
function http_req_mt.__index.read_body(self, sink)
	if self.method ~= 'POST' then return "only support POST" end
	if not self.body_read then
		receive_body(self.sock, self.headers, sink)
		self.body_read = true
	end
end

function http_req_mt.__index.get_uri_args(self)
	if not self.uri_args then
		self.uri_args = decode_args(self.url:query())
	end
	return self.uri_args
end

function http_req_mt.__index.get_post_args(self)
	if self.method ~= "POST" then return nil, "not POST" end
	if not self.post_args then
		receive_body(self.sock, self.headers, function(chunk)
			self.post_args = decode_args(chunk)
		end)
	end
	return self.post_args
end

local function http_req_new(method, url, headers, sock)
	return setmetatable({body_read = false,
		method = method, url = url,
		headers = headers, sock = sock}, http_req_mt)
end

local http_rsp_mt = {__index={}}

function http_rsp_mt.__index.send_headers(self)
	return run_next_header_filter(self)
end

local function calc_buf_size(buf)
	local size = 0
	for i,v in ipairs(buf) do
		local typ = type(v)
		if typ == "table" then
			size = size + calc_buf_size(v)
		else
			if typ ~= "string" then
				buf[i] = tostring(v)
				v = buf[i]
			end
			size = size + #v
		end
	end
	return size
end

function http_rsp_mt.__index.say(self, ...)
	local buf = {size=0, ...}

	-- supply nil arguments
	local n_arg = select("#", ...)
	if #buf ~= n_arg then
		for i=1,n_arg do
			local arg = select(i, ...)
			if type(arg) == "nil" then
				tinsert(buf, i, "nil")
			end
		end
	end

	buf.size = calc_buf_size(buf)
	return run_next_body_filter(self, buf)
end

function http_rsp_mt.__index.sendfile(self, path, offset, size, eof)
	local buf = {is_file=true, path=path, offset=offset, size=size, eof=eof}
	return run_next_body_filter(self, buf)
end

function http_rsp_mt.__index.flush(self, status)
	return run_next_body_filter(self, {size=0, flush=true})
end

function http_rsp_mt.__index.finalize(self, status)
	if not self.status then self.status = status end
	return run_next_body_filter(self, {size=0, eof=true})
end

function http_rsp_mt.__index.exit(self, status)
	if not self.status then self.status = status end
	return coroutine.exit()
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
	return coroutine.exit()
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
	return coroutine.exit()
end

local function http_rsp_new(req, sock)
	return setmetatable({headers_sent = false, headers = {},
		sock = sock, req = req, status=200}, http_rsp_mt)
end

local g_http_cfg

local function http_parse_conf(cfg)
	g_http_cfg = cfg

	local function more_than(a,b)
		return a > b
	end

	local global_mt = {__index=cfg}
	for _,srv in ipairs(cfg) do
		setmetatable(srv, global_mt)
		srv.location_hash = {
			exact_hash={},
			prefix_hash={},
			postfix_hash={}, postfix_hash_len=0,
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
			elseif location[1] == "$" then
				shash.postfix_hash[location[2]] = location
				shash.postfix_hash_len = shash.postfix_hash_len + 1
			else
				tinsert(shash.pattern, location)
			end
		end

		local tmp = {}
		for k in pairs(shash.prefix_hash) do
			tmp[#k] = 1
		end
		shash.prefix_size_hash = {}
		for k in pairs(tmp) do
			tinsert(shash.prefix_size_hash, k)
		end
		tsort(shash.prefix_size_hash, more_than)
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

			local tmp = {}
			for k in pairs(srv_list.prefix_hash) do
				tmp[#k] = 1
			end
			srv_list.prefix_size_hash = {}
			for k in pairs(tmp) do
				tinsert(srv_list.prefix_size_hash, k)
			end
			tsort(srv_list.prefix_size_hash, more_than)

			srv_list.postfix_size_hash = {}
			local tmp = {}
			for k in pairs(srv_list.postfix_hash) do
				tmp[#k] = 1
			end
			for k in pairs(tmp) do
				tinsert(srv_list.postfix_size_hash, k)
			end
			tsort(srv_list.postfix_size_hash, more_than)
		end
	end
end

local mime_types = {
	["txt"] = "text/plain",
	["html"] = "text/html",
	["htm"] = "text/html",
	["shtml"] = "text/html",
	["css"] = "text/css",
	["xml"] = "text/xml",
	["rss"] = "text/xml",
	["gif"] = "image/gif",
	["jpeg"] = "image/jpeg",
	["jpg"] = "image/jpeg",
	["js"] = "application/x-javascript",
}

local function try_file(req, rsp, cfg)
	local path = req.url:path()
	local ext = string.match(path, "%.([^%.]+)$")
	rsp.headers["content-type"] = mime_types[ext] or "application/octet-stream"
	local fpath = (cfg.root or ".") .. '/' .. path
	local f = io.open(fpath)
	assert(f)
	local flen = f:seek('end')
	f:close()
	rsp.headers["content-length"] = flen

	local sent,err = rsp:sendfile(fpath, 0, flen, true)
	if err then
		return rsp:finalize(404)
	end
	return sent
end

local function match_aux(...)
	local n_capture = select("#", ...)
	if n_capture > 0 then
		return {...}
	end
end

local function do_location(req, rsp)
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
			for _,v in ipairs(srv_list.prefix_size_hash) do
				if srv_list.prefix_hash[strsub(host, hlen-v+1)] then
					match_srv = v.srv
					break
				end
			end
		end

		-- longest wildcard name ending with an asterisk, e.g. "mail.*"
		if not match_srv then
			for _,v in ipairs(srv_list.postfix_size_hash) do
				if srv_list.postfix_hash[strsub(host, 1, v)] then
					match_srv = v.srv
					break
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

		-- postfix match
		if not match_done then
			if shash.postfix_hash_len > 0 then
				local p = C.strrchr(path, 46)
				if p ~= nil then
					local postfix = ffi.string(p + 1)
					location = shash.postfix_hash[postfix]
					if location then match_done = true end
				end
			end
		end

		-- prefix match
		if not match_done then
			for _,v in ipairs(shash.prefix_size_hash) do
				local slcf = shash.prefix_hash[strsub(path, 1, v)]
				if slcf then
					location = slcf
					match_done = (slcf[1] == "^~")
					break
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
					req.match_data = match_aux(strmatch(lower(path), lower(pat)))
				elseif modifier == "f"  then
					req.match_data = match_aux(pat(req))
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
		local fn = location[3]
		local ret, err
		if type(fn) == 'string' then
			fn = require(fn)
		end
		assert(type(fn) == 'function')
		coroutine.spawn(fn, nil, req, rsp)
		coroutine.wait_descendants()
		if rsp.exec == true then
			rsp.exec = false
			goto location_matching
		end
		return rsp:finalize()
	end

	return try_file(req, rsp, match_srv)
end

local function http_handler(sock)
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
		do_location(req, rsp)
		sock.read_quota = nil
		if headers["connection"] == "close" then
			break
		end
	end
end

local function run(cfg)
	return tcp(cfg, http_parse_conf, http_handler)
end

return run
