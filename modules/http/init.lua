require("core.base")
local ffi = require("ffi")
local tcp = require("socket.tcp_mod")

local function unescape(s)
	s = string.gsub(s,"+"," ")
	return (string.gsub(s, "%%(%x%x)", function(hex)
		return string.char(tonumber(hex, 16))
	end))
end

-- <url> ::= <scheme>://<authority>/<path>;<params>?<query>#<fragment>
-- <authority> ::= <userinfo>@<host>:<port>
-- <userinfo> ::= <user>[:<password>]
-- <path> :: = {<segment>/}<segment>
local function parse_url(url, default)
	-- initialize default parameters
	local parsed = {}
	for i,v in pairs(default or parsed) do parsed[i] = v end

	-- get fragment
	url = string.gsub(url, "#(.*)$", function(f)
		parsed.fragment = f
		return ""
	end)

	-- get scheme
	url = string.gsub(url, "^([%w][%w%+%-%.]*)%:",
		function(s) parsed.scheme = s; return "" end)

	-- get authority
	url = string.gsub(url, "^//([^/]*)", function(n)
		parsed.authority = n
		return ""
	end)

	-- get query string
	url = string.gsub(url, "%?(.*)", function(q)
		parsed.query = {}
		for k,v in string.gmatch(q,"([^&=]+)=([^&=]+)") do
			parsed.query[k] = unescape(v)
		end
		return ""
	end)

	-- get params
	url = string.gsub(url, "%;(.*)", function(p)
		parsed.params = p
		return ""
	end)

	-- path is whatever was left
	if url ~= "" then parsed.path = unescape(url) end
	local authority = parsed.authority
	if not authority then return parsed end
	authority = string.gsub(authority,"^([^@]*)@",
		function(u) parsed.userinfo = u; return "" end)
	authority = string.gsub(authority, ":([^:%]]*)$",
		function(p) parsed.port = p; return "" end)
	if authority ~= "" then
		-- IPv6?
		parsed.host = string.match(authority, "^%[(.+)%]$") or authority
	end
	local userinfo = parsed.userinfo
	if not userinfo then return parsed end
	userinfo = string.gsub(userinfo, ":([^:]*)$",
		function(p) parsed.password = p; return "" end)
	parsed.user = userinfo

	return parsed
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
		name, value = string.match(line, "^(.-):%s*(.*)")
		if not (name and value) then return nil, "malformed reponse headers" end
		name = string.lower(name)
		-- get next line (value might be folded)
		line, err = sock:receive()
		if err then return nil, err end
		-- unfold any folded values
		while string.find(line, "^%s") do
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
			local size = tonumber(string.gsub(line, ";.*", ""), 16)
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

local status_tbl = {
	[200] = "HTTP/1.1 200 OK\r\n";
	[400] = "HTTP/1.1 400 Bad Request\r\n";
	[403] = "HTTP/1.1 403 Forbidden\r\n";
	[404] = "HTTP/1.1 404 Not Found\r\n";
	[500] = "HTTP/1.1 500 Internal Server Error\r\n";
	[501] = "HTTP/1.1 501 Not Implemented\r\n";
	[503] = "HTTP/1.1 503 Service Unavailable\r\n";
}

local http_rsp_mt = {__index={}}

local v_time_t = ffi.new("time_t[1]")
local date_buf = ffi.new("char[?]", 200)
local tm = ffi.new("struct tm[1]")
local function http_time()
	assert(ffi.C.time(v_time_t) > 0)
	assert(ffi.C.gmtime_r(v_time_t, tm))
	local len = ffi.C.strftime(date_buf, 200, "%a, %d %h %G %H:%M:%S GMT", tm)
	assert(len > 0)
	return ffi.string(date_buf, len)
end

function http_rsp_mt.__index.send_headers(self)
	if not self.headers_sent then
		local sk = self.sock
		local status = status_tbl[self.status or 200] or status_tbl[500]
		local ret,err = sk:send(status)
		if err then return err end

		-- adjust headers
		if not self.headers["content-length"] then
			self.headers["transfer-encoding"] = "chunked"
		end
		if not self.headers["content-type"] then
			self.headers["content-type"] = "text/plain; charset=utf-8"
		end

		self.headers["server"] = "luajit.io"

		self.headers["date"] = http_time()
		self.headers["cache-control"] = "no-cache, private"
		self.headers["connection"] = "Keep-Alive"

		if self.req.headers["connection"] == "close" then
			self.headers["connection"] = "close"
		end

		if not self.output_buf then self.output_buf = {} end
		local tbl = self.output_buf
		local eol = "\r\n"
		local sep = ": "
		for f, v in pairs(self.headers) do
			table.insert(tbl, f)
			table.insert(tbl, sep)
			table.insert(tbl, v)
			table.insert(tbl, eol)
		end
		table.insert(tbl, eol)

		local ret,err = sk:send(tbl)
		if err then return err end
		self.headers_sent = true
	end
end

local postpone_output = 1460

function http_rsp_mt.__index.say(self, ...)
	local err = self:send_headers()
	if err then return nil,err end

	if not self.is_chunked then
		self.is_chunked = self.headers["transfer-encoding"] == "chunked"
	end
	local tbl = self.output_buf
	if not self.output_buf_bytes then self.output_buf_bytes = 0 end
	if not self.output_buf_idx then self.output_buf_idx = 1 end
	local eol = "\r\n"
	for i=1,select("#",...) do
		local str = select(i,...)
		local len = #str
		self.output_buf_bytes = self.output_buf_bytes + len
		if self.is_chunked then
			local size = string.format("%X\r\n", len)
			tbl[self.output_buf_idx] = size
			self.output_buf_idx = self.output_buf_idx + 1
			self.output_buf_bytes = self.output_buf_bytes + #size
			tbl[self.output_buf_idx] = str
			self.output_buf_idx = self.output_buf_idx + 1
			tbl[self.output_buf_idx] = eol
			self.output_buf_idx = self.output_buf_idx + 1
			self.output_buf_bytes = self.output_buf_bytes + 1
		else
			tbl[self.output_buf_idx] = str
			self.output_buf_idx = self.output_buf_idx + 1
		end
	end

	if self.output_buf_bytes >= postpone_output then
		tbl[self.output_buf_idx] = nil
		self.output_buf_idx = 1
		self.output_buf_bytes = 0
		local ret,err = self.sock:send(tbl)
		if err then return nil,err end
	end

	return 1
end

function http_rsp_mt.__index.flush(self)
	if self.output_buf_bytes and self.output_buf_bytes > 0 then
		local tbl = self.output_buf
		tbl[self.output_buf_idx] = nil
		self.output_buf_idx = 1
		self.output_buf_bytes = 0
		local ret,err = self.sock:send(tbl)
		if err then return err end
	end
	return 1
end

local function http_req_new(method, url, headers, sock)
	return setmetatable({body_read = false,
		method = method, url = url,
		headers = headers, sock = sock}, http_req_mt)
end

local function http_rsp_new(req, sock)
	return setmetatable({headers_sent = false, headers = {}, sock = sock, req = req}, http_rsp_mt)
end

local g_http_cfg

local function do_servlet(req, rsp)
	local sk = req.sock
	local target_srv
	local host = req.headers["host"]
	for _,srv in ipairs(g_http_cfg.srv_tbl[sk.srv_port][sk.srv_ip]) do
		for _,h in pairs(srv.host) do
			if h == host then
				target_srv = srv
				break
			elseif h:sub(1,1) == "~" then
				if string.find(host, h:sub(2)) then
					target_srv = srv
					break
				end
			end
		end
		if not target_srv then target_srv = srv end
	end

	local servlet
	if target_srv then
		local longest_n = 0
		local path = req.url.path
		local idx
		local match_done = false
		for i,slcf in ipairs(target_srv.servlet) do
			local modifier,pat = slcf[1],slcf[2]
			if modifier == "=" then
				if path == pat then
					idx = i
					match_done = true
					break
				end
			elseif modifier == "^" or modifier == "^~" then
				local s,e = string.find(path, pat, 1, true)
				if s and e > longest_n then
					longest_n, idx, match_done = e, i, (modifier == "^~")
				end
			end
		end

		if match_done == true then
			servlet = target_srv.servlet[idx]
		else
			for i,slcf in ipairs(target_srv.servlet) do
				local modifier,pat = slcf[1],slcf[2]
				if modifier == "~" then
					if string.find(path, pat) then
						idx = i
						break
					end
				elseif modifier == "~*" then
					if string.find(string.lower(path), string.lower(pat)) then
						idx = i
						break
					end
				elseif modifier == "f"  then
					if pat(req) then
						idx = i
						break
					end
				end
			end
			if idx then servlet = target_srv.servlet[idx] end
		end
	end

	if servlet then
		local fn = servlet[3]
		local extra = servlet[4]
		local ret, err
		if type(fn) == 'string' then
			fn = require(fn)
			assert(fn)
			ret,err = fn.service(req,rsp,target_srv,extra)
		elseif type(fn) == 'function' then
			ret,err = fn(req,rsp,target_srv,extra)
		end
		if not err then
			rsp:flush()
			if rsp.headers["transfer-encoding"] == "chunked" then
				ret,err = rsp.sock:send("0\r\n\r\n")
			end
		end
		if err then
			print(err)
			return false
		end
	else
		print "no servlet"
	end
end

local function http_request_handler(sock)
	while true do
		local line,err = sock:receive()
		if err then print(err); break end
		local method,url,ver = string.match(line, "(.*) (.*) HTTP/(%d%.%d)")
		url = parse_url(url)
		local headers = receive_headers(sock)
		local req = http_req_new(method, url, headers, sock)
		local rsp = http_rsp_new(req, sock)
		local success = do_servlet(req, rsp)
		if (success == false) or headers["connection"] == "close" then
			break
		end
	end
end

local function run(cfg)
	g_http_cfg = cfg
	return tcp(cfg, http_request_handler)
end

return run
