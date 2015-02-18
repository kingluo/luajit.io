package.path = package.path .. ";./modules/?.lua;./modules/?/init.lua;./modules/http/?.lua"
	.. ";/usr/share/lua/5.1/?.lua;/usr/share/lua/5.1/?/init.lua"
package.cpath = package.cpath .. ";./modules/?.so"

require("http") {
	strict = true,
	user = "nobody",
	group = "nogroup",
	daemon = false,
	log_level = "debug",
	log_stderr = true,
	worker_processes = 1,
	worker_connections = 2,
	-- Server blocks
	-- See http://nginx.org/en/docs/http/request_processing.html
	{
		listen = {
			{port=8080,default_server=1}
		},
		server_name = {"example.org", "*.example.com", "~my%d+web%.org"},
		root = "/srv/myserver",
		default_type = 'text/plain',
		servlet = {
			-- See nginx location directive:
			-- http://nginx.org/en/docs/http/ngx_http_core_module.html#location
			-- Add two new modifiers:
			-- "^" explicitly denotes longest prefix matching
			-- "$" means postfix matching, if matched, regexp match would be skipped
			-- "f" means matching function, with same matching priority as regexp matching
			-- {<modifier>, (<url match pattern> | <match function>), (<module name> | <inline function>), ...}
			{"=", "/test2", "test_mod"},
			{"^", "/foobar", "foobar_mod"},
			{"$", "lux", "lux_mod", path="WEB-INF/lux/"},
			{"^~", "/static/", "static_mod"},
			{
				"f",
				function(req)
					return req.headers["user-agent"]:find("curl")
				end,
				"test_mod"
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
