package.path = package.path .. ';./modules/?.lua'
package.cpath = package.cpath .. ';./modules/?.so'

local function test_servlet(req, rsp, cf, extra)
	local co1 = co_spawn(function() co_sleep(3); rsp:say("hello world, conf ok!\n") end)
	local co2 = co_spawn(function() rsp:say("hello xxx, conf ok!\n") end)
	--co_wait(co1); co_wait(co2)
	--return rsp:say("hello world, conf ok!\n")
end

http_conf {
	-- server blocks
	{
		listen = "192.168.8.30:8080",
		-- if host prefixed by "~", denotes regular pattern matching
		-- otherwise, do exact compare
		host = {"example.com", "~.*%.example%.com"},
		root = ".",
		default_type = 'text/plain',
		servlet = {
			-- same match rule as Nginx location directive
			-- see http://nginx.org/en/docs/http/ngx_http_core_module.html#location
			-- Add two new modifiers:
			-- "^" explicitly denotes longest prefix matching
			-- "f" denotes matching function
			-- {<Nginx-style modifier> (<url match pattern>|<match function>), (<module name>|<servlet function>)}, [<extra>]
			{"=", "/test", test_servlet},
			{"^", "/foobar", "foobar_mod"},
			{"~", "%.lux$", "lux_mod"},
			{"^~", "/files/", "static_mod"},
			{
				"f",
				function(req)
					return true
				end,
				test_servlet,
				{foo=1,bar="hello"}
			},
		}
	},
	{
		listen = "192.168.8.30:8080; 127.0.0.1:8080; *:9090; 127.0.0.1:10000",
		host = {"example.net"},
		root = "/srv/foobar",
		default_type = 'text/plain',
		servlet = {
			{"^", "/static/files/", "static_mod"}
		}
	},
}