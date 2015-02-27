local dns = require("socket.dns")

local function test_coroutine(req, rsp)
	local co1 = coroutine.spawn(
		function()
			rsp:say("foo")
			rsp:flush()
		end
	)

	local co2 = coroutine.spawn(
		function()
			rsp:say(dns.resolve("localhost", 80))
			rsp:flush()
			coroutine.sleep(2)
			rsp:exit()
			rsp:say("bar")
			rsp:flush()
		end
	)
end

return test_coroutine
