package.path = package.path .. ";./modules/?.lua;./modules/?/init.lua"

require("http") {
	-- toggle strict global env
	strict = true,

	-- logging
	log_level = "debug",
	log_stderr = true,
	log_import_print = false,

	user = "nobody",
	group = "nogroup",
	daemon = false,
	worker_processes = 1,
	worker_connections = 2,

	ssl = true,
	ssl_certificate = "/opt/carbox/sslkey/server.crt",
	ssl_certificate_key = "/opt/carbox/sslkey/server.key",
	ssl_ciphers = "RC4:HIGH:!aNULL:!MD5",

	lua_shared_dict = {
		test = "10M",
	},

	-- Server blocks
	-- Refer to http://nginx.org/en/docs/http/request_processing.html
	{
		listen = {
			{port=8080,default_server=true,ssl=true},
			{address="unix:/var/run/test.sock"}
		},
		server_name = {"example.org", "*.example.com", "~my%d+web%.org"},
		root = "/srv/myserver",
		default_type = 'text/plain',
		servlet = {
			-- Refer to nginx location directive:
			-- http://nginx.org/en/docs/http/ngx_http_core_module.html#location
			-- Add three new modifiers:
			-- "^" explicitly longest prefix matching
			-- "$" postfix matching, just after exact matching, return if matched
			-- "f" matching function for arbitrary matching, with same priority as regexp matching
			--
			-- {<modifier>, (<pattern> | <match function>), (<module> | <inline function>), ...}
			{"=", "/test2", "test"},
			{"^", "/foobar", "foobar_mod"},
			{"$", "luax", "http.luax", alias="WEB-INF/luax/"},
			{
				"f",
				function(req)
					return string.find(req.url:path(), "^/test")
				end,
				"test"
			},
		}
	},
	{
		listen = {
			{address="127.0.0.1", port=8080},
			{address="127.0.0.1", port=10000}
		},
		server_name = {"example.net"},
		root = "/srv/foorbar",
		default_type = 'text/plain',
		servlet = {
			{"^~", "/static/", "static_mod"}
		}
	},
}
