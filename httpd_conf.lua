package.path = package.path .. ';./modules/?.lua;./modules/?/init.lua;/usr/share/lua/5.1/?.lua;/usr/share/lua/5.1/?/init.lua'
package.cpath = package.cpath .. ';./modules/?.so'

require("pl.strict")

local http = require("http")

http {
	worker_processes = 1,
	worker_connections = 2,
	-- server blocks
	{
		listen = "*:8080",
		-- if host prefixed by "~", denotes regular pattern matching
		-- otherwise, do exact compare
		host = {"example.com", "~.*%.example%.com"},
		root = "/srv/luajit.io/",
		default_type = 'text/plain',
		servlet = {
			-- same match rule as Nginx location directive
			-- see http://nginx.org/en/docs/http/ngx_http_core_module.html#location
			-- Add two new modifiers:
			-- "^" explicitly denotes longest prefix matching
			-- "f" denotes matching function
			-- {<Nginx-style modifier> (<url match pattern>|<match function>), (<module name>|<servlet function>)}, [<extra>]
			{"=", "/test2", "test_mod"},
			{"^", "/foobar", "foobar_mod"},
			{"~", "%.lux$", "lux_mod"},
			{"^~", "/files/", "static_mod"},
			{
				"f",
				function(req)
					return true
				end,
				function(...)
					local test = require("test_mod")
					return test.service(...)
				end,
				{foo=1,bar="hello"}
			},
		}
	},
	{
		listen = "127.0.0.1:8080; *:9090; 127.0.0.1:10000",
		host = {"example.net"},
		root = "./foorbar",
		default_type = 'text/plain',
		servlet = {
			{"^", "/static/files/", "static_mod"}
		}
	},
}
