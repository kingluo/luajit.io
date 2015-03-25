-- Copyright (C) Jinhua Luo

local C = require("ljio.cdef")
local ffi = require("ffi")
local tcp = require("ljio.socket.tcp")
local master = require("ljio.core.master")
local signal = require("ljio.core.signal")
local log = require("ljio.core.logging").log

local strfind = string.find
local strsub = string.sub
local strmatch = string.match
local tinsert = table.insert

local g_listen_sk_tbl = {}
local g_tcp_cfg

local function add_ssock(port, address, linfo, srv)
	if g_tcp_cfg == nil or g_tcp_cfg.srv_tbl[port] == nil
		or g_tcp_cfg.srv_tbl[port][address] == nil then
		local ssock = tcp.new()
		ssock.linfo = linfo
		ssock.srv = srv
		local r,err = ssock:bind(address, port)
		if err then error(err) end
		g_listen_sk_tbl[ssock.fd] = ssock
	end
end

local function tcp_parse_conf(cfg)
	local inherited_fdlist = os.getenv("LUAJITIO")
	if inherited_fdlist then
		C.unsetenv("LUAJITIO")
		local addr = ffi.cast("struct sockaddr *", ffi.new("char[512]"))
		local len = ffi.new("unsigned int[1]", ffi.sizeof(addr))
		for fd in string.gmatch(inherited_fdlist, "%d+") do
			fd = tonumber(fd)
			len[0] = 512
			assert(C.getsockname(fd, addr, len) == 0)

			local sock = tcp.new(fd)
			sock.family = addr.sa_family

			if addr.sa_family == C.AF_INET then
				local addr2 = ffi.cast("struct sockaddr_in*", addr)
				sock.ip = ffi.string(C.inet_ntoa(addr2.sin_addr))
				if sock.ip == "0.0.0.0" then
					sock.ip = "*"
				end
				sock.port = C.htons(tonumber(addr2.sin_port))
			else
				local addr2 = ffi.cast("struct sockaddr_un*", addr)
				sock.ip = "unix:" .. ffi.string(addr2.sun_path)
				sock.port = "unix"
			end
			g_listen_sk_tbl[fd] = sock
		end
	end

	local srv_tbl = {}

	for _,srv in ipairs(cfg) do
		if not srv.listen then
			srv.listen = {{address="*", port=((C.getuid() == 0) and 80 or 8000)}}
		end

		for _,linfo in ipairs(srv.listen) do
			local port = linfo.port
			if linfo.address then
				local path = strmatch(linfo.address, "^unix:(.+)$")
				if path then
					port = "unix"
				end
			else
				linfo.address = "*"
			end

			if not srv_tbl[port] then
				srv_tbl[port] = {}
			end

			local address = linfo.address

			if not srv_tbl[port][address] then
				srv_tbl[port][address] = {}
				srv_tbl[port][address].linfo = linfo
				if linfo.default_server then
					srv_tbl[port][address].default_server = srv
				end
			end

			tinsert(srv_tbl[port][address], srv)
		end
	end

	if not inherited_fdlist then
		for port, addresses in pairs(srv_tbl) do
			if addresses["*"] then
				add_ssock(port, "*", addresses["*"].linfo, addresses["*"][1])
			else
				for address, srv_list in pairs(addresses) do
					add_ssock(port, address, srv_list.linfo, srv_list[1])
				end
			end
		end

		for fd, ssock in pairs(g_listen_sk_tbl) do
			if srv_tbl[ssock.port] == nil or srv_tbl[ssock.port][ssock.ip] == nil then
				g_listen_sk_tbl[fd] = nil
				ssock:close()
			end
		end
	else
		for _, ssock in pairs(g_listen_sk_tbl) do
			ssock.linfo = srv_tbl[ssock.port][ssock.ip].linfo
		end
	end

	cfg.srv_tbl = srv_tbl
	cfg.listen_fdlist = g_listen_sk_tbl

	if cfg.worker_connections == nil then
		cfg.worker_connections = 512
	end

	g_tcp_cfg = cfg
end

local function tcp_handler(sock)
	local srv_list = g_tcp_cfg.srv_tbl[sock.srv_port][sock.srv_ip]
		or g_tcp_cfg.srv_tbl[sock.srv_port]["*"]
	local srv = srv_list[1]
	local handler = srv.handler
	if type(handler) == 'string' then
		return require(handler).service(srv)
	elseif type(handler) == 'function' then
		return handler(srv)
	end
end

local function do_all_listen_sk(func)
	for _, ssock in pairs(g_listen_sk_tbl) do
		func(ssock)
	end
end

local function init_worker(conn_handler)
	local shutting_down = false
	local connections = 0
	local wait_listen_sk = false

	local ssock_handler = function(ev)
		local sock,err = ev.sock:accept()
		if sock then
			log("debug", "worker pid=", C.getpid() .. " get new connection, fd=" .. sock.fd .. ", port=" .. sock.port)
			connections = connections + 1
			if connections >= g_tcp_cfg.worker_connections then
				print("worker pid=" .. C.getpid() .. " unlisten sk")
				do_all_listen_sk(function(ssock) epoll.del_event(ssock.ev) end)
				wait_listen_sk = false
			end
			coroutine.spawn(
				conn_handler,
				function()
					-- print("worker pid=" .. C.getpid() .. " remove connection, fd=" .. sock.fd)
					sock:close()
					connections = connections - 1

					if shutting_down and connections == 0 then
						os.exit()
					end

					if wait_listen_sk == false and connections < g_tcp_cfg.worker_connections then
						print("worker pid=" .. C.getpid() .. " listen sk")
						do_all_listen_sk(function(ssock) epoll.add_event(ssock.ev, C.EPOLLIN) end)
						wait_listen_sk = true
					end
				end,
				sock
			)
		else
			print("worker pid=" .. C.getpid() .. " accept error: " .. err)
		end
	end

	-- listen all server sockets
	do_all_listen_sk(function(ssock)
		local r,err = ssock:listen(100, ssock_handler)
		if err then error(err) end
	end)
	wait_listen_sk = true

	signal.add_signal_handler(C.SIGQUIT, function()
		if connections == 0 then
			os.exit()
		end
		shutting_down = true
		do_all_listen_sk(function(ssock) epoll.del_event(ssock.ev) end)
	end)

	signal.add_signal_handler(C.SIGTERM, function() os.exit() end)
	signal.add_signal_handler(C.SIGINT, function() os.exit() end)
end

local function run(cfg, parse_conf, conn_handler)
	return master.run(cfg,
		function(cfg) tcp_parse_conf(cfg); if parse_conf then parse_conf(cfg) end end,
		function() return init_worker(conn_handler or tcp_handler) end)
end

return run
