
local function test(req, rsp)
	local test = require("ljio.core.shdict").shared.test
	test:set("foo","bar")
	rsp:say(test:get("foo"))
	test:set("foo",98767)
	rsp:say(test:get("foo"))
	rsp:say(test:get_keys())
end

return test
