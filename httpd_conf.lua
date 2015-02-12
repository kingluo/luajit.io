package.path = package.path .. ';./modules/?.lua;./modules/?/init.lua;/usr/share/lua/5.1/?.lua;/usr/share/lua/5.1/?/init.lua'
package.cpath = package.cpath .. ';./modules/?.so'

require("pl.strict")

local http = require("http")
local co = require("core.co_mod")
local dns = require("socket.dns_mod")
local pg = require("resty.postgres")

local function getdb()
	local db = pg:new()
	db:set_timeout(3000)
	local ok, err = db:connect({host="127.0.0.1",port=5432,database="test",
		user="test",password="test",compact=false})
	return db,err
end

local function test_fn(req, rsp, cf, extra)
	-- local co1 = co.spawn(function() co.yield(); co.sleep(2); rsp:say("hello world, conf ok!\n") end)
	-- local co2 = co.spawn(function() rsp:say("hello xxx, conf ok!\n") end)
	-- co.sleep(0.2)
	-- assert(co.wait(co1))
	-- assert(co.wait(co2))
	--while true do
	-- print(dns.resolve("localhost", 80))
	-- collectgarbage()
	--end
	local db,err = getdb()
	if err then print(err); os.exit(1); end
	local sqlstr = [[
		select * from send_sms_tbl order by id;
	]]
	local res,err,err_msg,tstatus = db:query(sqlstr)
	if not res then
		print(err)
	else
		for i,v in ipairs(res) do
			print(v.id, v.sendtime, v.status)
		end
	end
	db:set_keepalive()
	return rsp:say("hello world, conf ok!\n")
end

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
				test_fn,
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
