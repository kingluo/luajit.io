local dns = require("socket.dns")

local function test_coroutine(req, rsp)
	local co1 = coroutine.spawn(
		function()
			rsp:say("foo\n")
			rsp:flush()
		end
	)

	local co2 = coroutine.spawn(
		function()
			rsp:say(dns.resolve("localhost", 80), "\n")
			rsp:flush()
			coroutine.sleep(2)
			coroutine.exit(true)
			rsp:say("bar\n")
			rsp:flush()
		end
	)

	print(coroutine.wait(co1))
	print(coroutine.wait(co2))
end

return test_coroutine
